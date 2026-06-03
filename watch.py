#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = ["rich", "click", "pyyaml==6.0.3", "pydantic>=2", "pyln-proto==26.04.1"]
# ///

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from typing import Any

import click
import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text

# Lightning - using the high-level API from pyln-proto v26.04.1
try:
    from pyln.proto.primitives import PrivateKey
    from pyln.proto.wire import connect as lightning_connect
except ImportError:
    lightning_connect = None
    PrivateKey = None


class TaskSpec(BaseModel):
    """Pydantic model for validating a single task entry from YAML."""

    name: str
    type: str
    depends_on: list[str] = Field(default_factory=list)
    description: str = ""

    model_config = ConfigDict(extra="allow")


class Status(StrEnum):
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCESS = "Success"
    FAILED = "Failed"
    SKIPPED = "Skipped"


class Task:
    def __init__(self, spec: TaskSpec):
        self.name: str = spec.name
        self.type: str = spec.type
        self.depends_on: list[str] = spec.depends_on
        self.description: str = spec.description or ""
        self.failed_ancestor = None

        self.params: dict[str, Any] = {
            k: v
            for k, v in spec.model_dump().items()
            if k not in ("name", "type", "depends_on", "description")
        }

        self.status: Status = Status.PENDING
        self.success: bool | None = None
        self.detail: str = ""

    def run(self) -> tuple[bool, str]:
        runner = TASK_RUNNERS.get(self.type, run_unknown)
        success, message = runner(self)
        self.success = success
        self.detail = message
        return success, message


# ------------------------------------------------------------------
# Helper for JSON-RPC style handshakes (used by electrum and stratum)
# ------------------------------------------------------------------


def _wait_for_jsonrpc_response(
    sock: socket.socket,
    request_id: int,
    host: str,
    port: int,
    timeout: float = 10.0,
) -> dict:
    """
    Read newline-delimited JSON-RPC lines until we receive a response
    whose 'id' matches the one we sent.

    Any non-empty line that is not valid JSON will cause the handshake to fail
    (the exception will propagate to the caller).
    """
    sock.settimeout(timeout)
    file = sock.makefile("r", encoding="utf-8", newline="\n")

    for line in file:
        line = line.strip()
        if not line:
            continue
        # Do NOT catch JSONDecodeError here.
        # If the line is not valid JSON, we want the handshake to fail.
        data = json.loads(line)
        if isinstance(data, dict) and data.get("id") == request_id:
            return data

    raise RuntimeError(f"No JSON-RPC response with id={request_id} received from {host}:{port}")


# ------------------------------------------------------------------
# Bitcoin P2P protocol helpers (for the 'bitcoin' task type)
# ------------------------------------------------------------------

BITCOIN_MAGIC = b"\xf9\xbe\xb4\xd9"
BITCOIN_VERSION = 70016
BITCOIN_USER_AGENT = b"/network-watch:0.1/"


def _make_net_addr(services: int, ip: bytes, port: int) -> bytes:
    """Pack a Bitcoin net_addr (services + 16-byte IP + port BE)."""
    return struct.pack(">Q16sH", services, ip, port)


def _bitcoin_checksum(payload: bytes) -> bytes:
    """Double-SHA256 checksum, first 4 bytes."""
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def _build_version_message() -> bytes:
    """Build a minimal Bitcoin 'version' message (mainnet)."""
    timestamp = int(time.time())
    services = 0
    dummy_ip = b"\x00" * 10 + b"\xff\xff" + b"\x00\x00\x00\x00"

    addr_recv = _make_net_addr(services, dummy_ip, 8333)
    addr_from = _make_net_addr(0, dummy_ip, 0)
    nonce = 0xDEADBEEFCAFEBABE

    ua = BITCOIN_USER_AGENT
    ua_var = struct.pack("B", len(ua)) + ua  # var_str, length < 0xfd

    payload = struct.pack("<iQq", BITCOIN_VERSION, services, timestamp)
    payload += addr_recv + addr_from
    payload += struct.pack("<Q", nonce)
    payload += ua_var
    payload += struct.pack("<iB", 0, 1)  # start_height + relay

    command = b"version" + b"\x00" * (12 - len(b"version"))
    length = len(payload)
    checksum = _bitcoin_checksum(payload)
    header = BITCOIN_MAGIC + command + struct.pack("<I4s", length, checksum)
    return header + payload


def _build_verack() -> bytes:
    """Build a Bitcoin 'verack' message (empty payload)."""
    command = b"verack" + b"\x00" * 6
    checksum = _bitcoin_checksum(b"")
    header = BITCOIN_MAGIC + command + struct.pack("<I4s", 0, checksum)
    return header + b""


def _read_bitcoin_message(sock: socket.socket, timeout: float = 10.0) -> tuple[str, bytes]:
    """Read a full Bitcoin P2P message (header + payload). Returns (command, payload)."""
    sock.settimeout(timeout)
    header = b""
    while len(header) < 24:
        chunk = sock.recv(24 - len(header))
        if not chunk:
            raise RuntimeError("connection closed reading header")
        header += chunk

    magic, command, length, checksum = struct.unpack("<4s12sI4s", header)
    if magic != BITCOIN_MAGIC:
        raise RuntimeError(f"bad magic {magic.hex()}")
    command = command.rstrip(b"\x00").decode("ascii", errors="ignore")

    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise RuntimeError("connection closed reading payload")
        payload += chunk

    # Checksum is verified leniently (proceed even if mismatch for robustness)
    return command, payload


def _parse_version_payload(payload: bytes) -> dict[str, Any]:
    """Best-effort parse of version payload for remote version + user agent."""
    if len(payload) < 85:
        return {"version": 0, "user_agent": "?"}
    try:
        version, _, _ = struct.unpack("<iQq", payload[0:20])
        off = 20 + 52  # skip two net_addrs
        off += 8  # nonce
        ua_len = payload[off]
        off += 1
        user_agent = payload[off : off + ua_len].decode("ascii", errors="ignore")
        off += ua_len
        start_height = struct.unpack("<i", payload[off : off + 4])[0]
        return {
            "version": version,
            "user_agent": user_agent or "?",
            "start_height": start_height,
        }
    except Exception:
        return {"version": 0, "user_agent": "parse-error"}


# ------------------------------------------------------------------
# Task Runners
# ------------------------------------------------------------------


def run_ping(task: Task) -> tuple[bool, str]:
    target = task.params.get("target")
    if not target:
        return False, "Missing required parameter 'target'"

    cmd = ["ping", "-c", "4", "-W", "2", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return False, f"Ping to {target} timed out after 15 seconds"
    except FileNotFoundError:
        return False, "The 'ping' command was not found on this system"
    except Exception as e:
        return False, f"Failed to execute ping: {e}"

    output = (result.stdout or result.stderr or "").strip()
    if result.returncode == 0:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return True, lines[-1] if lines else "Ping successful"
    else:
        error_msg = (
            output.splitlines()[-1] if output else f"Ping failed with exit code {result.returncode}"
        )
        return False, f"Ping to {target} failed: {error_msg}"


def run_http_get(task: Task) -> tuple[bool, str]:
    url = task.params.get("url")
    if not url:
        return False, "Missing required parameter 'url'"

    cmd = ["curl", "-sS", "-I", "--max-time", "10", url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return False, f"Request to {url} timed out after 15 seconds"
    except FileNotFoundError:
        return False, "The 'curl' command was not found on this system"
    except Exception as e:
        return False, f"Failed to execute curl: {e}"

    output = (result.stdout or "").strip()
    error = (result.stderr or "").strip()

    if result.returncode == 0:
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("HTTP/"):
                return True, line
        return True, "HTTP response received successfully"
    else:
        msg = error or output or f"curl exited with code {result.returncode}"
        return False, f"Failed to reach {url}: {msg}"


def run_dns_resolve(task: Task) -> tuple[bool, str]:
    host = task.params.get("host")
    if not host:
        return False, "Missing required parameter 'host'"

    cmd = ["host", host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return False, f"DNS resolution for {host} timed out"
    except FileNotFoundError:
        return False, "The 'host' command was not found on this system"
    except Exception as e:
        return False, f"Failed to execute host command: {e}"

    output = (result.stdout or result.stderr or "").strip()

    if result.returncode == 0:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return True, lines[-1] if lines else f"Successfully resolved {host}"
    else:
        error_msg = output or f"host exited with code {result.returncode}"
        return False, f"Failed to resolve {host}: {error_msg}"


def run_ssh(task: Task) -> tuple[bool, str]:
    """Check SSH port reachability and verify the host key matches the provided 'identity'."""
    target = task.params.get("target")
    expected_identity = task.params.get("identity")
    port = task.params.get("port", 22)

    if not target:
        return False, "Missing required parameter 'target'"
    if not expected_identity:
        return False, "Missing required parameter 'identity'"

    try:
        port = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid 'port' value: {port}"

    cmd = ["ssh-keyscan", "-p", str(port), "-T", "5", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return False, f"SSH keyscan to {target}:{port} timed out"
    except FileNotFoundError:
        return False, "The 'ssh-keyscan' command was not found on this system"
    except Exception as e:
        return False, f"Failed to run ssh-keyscan: {e}"

    output = (result.stdout or "").strip()
    error_output = (result.stderr or "").strip()

    if not output:
        msg = error_output or "No SSH host keys returned (port may be closed or filtered)"
        return False, f"Failed to retrieve SSH host key from {target}:{port}: {msg}"

    normalized_expected = expected_identity.strip()

    if normalized_expected in output:
        for line in output.splitlines():
            if normalized_expected in line.strip():
                verified_line = line.strip()
                # Shorten the public key part (last long token) for summary display
                parts = verified_line.split()
                if len(parts) >= 3:
                    key = parts[-1]
                    if len(key) > 16:
                        parts[-1] = key[:6] + "..." + key[-10:]
                        verified_line = " ".join(parts)
                return True, f"SSH host key verified: {verified_line}"
        return True, "SSH host key matches the provided identity"

    return (
        False,
        f"SSH host key mismatch on {target}:{port}. Expected identity not found in scan results.",
    )


def run_electrum(task: Task) -> tuple[bool, str]:
    """Connect to an Electrum server (with optional TLS) and perform a protocol handshake."""
    host = task.params.get("host")
    port = task.params.get("port")
    use_tls = bool(task.params.get("TLS", False))
    request_id = 1

    if not host:
        return False, "Missing required parameter 'host'"
    if not port:
        return False, "Missing required parameter 'port'"

    try:
        port = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid port value: {port}"

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)

            if use_tls:
                # Use TLS when explicitly requested
                context = ssl.create_default_context()
                # Many Electrum servers use self-signed certificates
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssock = context.wrap_socket(sock, server_hostname=host)
            else:
                ssock = sock

            # Electrum JSON-RPC handshake
            request = {
                "id": request_id,
                "method": "server.version",
                "params": ["network-watch", "1.4"],
            }
            message = json.dumps(request) + "\n"
            ssock.sendall(message.encode("utf-8"))

            data = _wait_for_jsonrpc_response(ssock, request_id, host, port)

            error = data.get("error")
            if error is not None:
                return False, f"Electrum server error: {error}"

            result = data.get("result")
            version = result[0] if isinstance(result, list) and result else str(result)
            tls_note = " (TLS)" if use_tls else ""
            return (
                True,
                f"Electrum server at {host}:{port}{tls_note} responded: {version}",
            )

    except TimeoutError:
        return False, f"Connection to {host}:{port} timed out"
    except ConnectionRefusedError:
        return False, f"Connection refused to {host}:{port}"
    except ssl.SSLError as e:
        return False, f"TLS error connecting to {host}:{port}: {e}"
    except json.JSONDecodeError:
        return False, f"Invalid JSON response received from {host}:{port}"
    except RuntimeError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Failed to connect to Electrum server: {e}"


def run_stratum(task: Task) -> tuple[bool, str]:
    """Perform a basic Stratum (Bitcoin mining) protocol handshake over plain TCP (no TLS)."""
    host = task.params.get("host")
    port = task.params.get("port")
    request_id = 1

    if not host:
        return False, "Missing required parameter 'host'"
    if not port:
        return False, "Missing required parameter 'port'"

    try:
        port = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid port value: {port}"

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)

            # Stratum v1 mining.subscribe handshake
            request = {
                "id": request_id,
                "method": "mining.subscribe",
                "params": ["network-watch/1.0"],
            }
            message = json.dumps(request) + "\n"
            sock.sendall(message.encode("utf-8"))

            data = _wait_for_jsonrpc_response(sock, request_id, host, port)

            error = data.get("error")
            if error is not None:
                return False, f"Stratum server error: {error}"

            return True, f"Stratum server at {host}:{port} responded successfully"

    except TimeoutError:
        return False, f"Connection to {host}:{port} timed out"
    except ConnectionRefusedError:
        return False, f"Connection refused to {host}:{port}"
    except json.JSONDecodeError:
        return False, f"Invalid JSON response received from {host}:{port}"
    except RuntimeError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Failed to connect to Stratum server: {e}"


def run_bitcoin(task: Task) -> tuple[bool, str]:
    """Perform a basic Bitcoin P2P protocol version handshake (mainnet magic)."""
    host = task.params.get("host")
    port = task.params.get("port", 8333)

    if not host:
        return False, "Missing required parameter 'host'"

    try:
        port = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid port value: {port}"

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            sock.settimeout(10)

            # Send our version message to initiate handshake
            version_msg = _build_version_message()
            sock.sendall(version_msg)

            # Read responses; we expect at least their 'version' reply.
            # We send 'verack' on receiving version. Success if we saw a version.
            got_version = False
            info = ""
            for _ in range(5):  # read a bounded number of messages
                try:
                    cmd, payload = _read_bitcoin_message(sock, timeout=8)
                except Exception:
                    if got_version:
                        break
                    raise

                if cmd == "version":
                    got_version = True
                    parsed = _parse_version_payload(payload)
                    ver = parsed.get("version", 0)
                    ua = parsed.get("user_agent", "?")
                    info = f"v{ver} {ua}".strip()
                    # Complete the handshake
                    sock.sendall(_build_verack())
                elif cmd == "verack" and got_version:
                    return True, f"Bitcoin peer at {host}:{port} handshake OK ({info})"

            if got_version:
                return True, f"Bitcoin peer at {host}:{port} responded with version ({info})"

            return False, f"No valid version response from Bitcoin peer at {host}:{port}"

    except TimeoutError:
        return False, f"Connection to {host}:{port} timed out"
    except ConnectionRefusedError:
        return False, f"Connection refused to {host}:{port}"
    except OSError as e:
        return False, f"Connection error to {host}:{port}: {e}"
    except Exception as e:
        return False, f"Bitcoin handshake failed: {e}"


def run_lightning(task: Task) -> tuple[bool, str]:
    """Connect to a Lightning node using pyln-proto (v26.04.1) high-level API."""
    if lightning_connect is None or PrivateKey is None:
        return False, "pyln-proto is not installed (required for 'lightning' tasks)"

    host = task.params.get("host")
    port = task.params.get("port")
    node_id_hex = task.params.get("node_id")

    if not host:
        return False, "Missing required parameter 'host'"
    if not port:
        return False, "Missing required parameter 'port'"
    if not node_id_hex:
        return (
            False,
            "Missing required parameter 'node_id' (33-byte compressed public key in hex)",
        )

    try:
        port = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid port value: {port}"

    try:
        node_id_bytes = bytes.fromhex(node_id_hex)
        if len(node_id_bytes) != 33:
            return False, "'node_id' must be 66 hex characters (33 bytes)"
    except Exception:
        return False, "Invalid 'node_id' (must be hex-encoded 33-byte public key)"

    try:
        # Use the high-level connect() helper from pyln-proto v26.04.1
        local_privkey = PrivateKey(os.urandom(32))
        lconn = lightning_connect(local_privkey, node_id_bytes, host, port)

        # Handshake succeeded
        remote_id = lconn.remote_pubkey.serializeCompressed().hex()
        short_id = remote_id[:6] + "..." + remote_id[-6:]
        return True, f"Connected to Lightning node {short_id}"

    except TimeoutError:
        return False, f"Connection to {host}:{port} timed out"
    except ConnectionRefusedError:
        return False, f"Connection refused to {host}:{port}"
    except Exception as e:
        return False, f"Lightning handshake failed: {e}"


def run_subsonic(task: Task) -> tuple[bool, str]:
    """Perform a Subsonic REST API handshake using /rest/ping.view.

    Supports modern token auth (default) and legacy plain-password auth
    (via legacy_auth=true) for older servers / Airsonic / LDAP users.
    """
    host = task.params.get("host")
    port = task.params.get("port")
    user = task.params.get("user")
    password = task.params.get("password")
    use_https = bool(task.params.get("https", False))
    legacy_auth = bool(task.params.get("legacy_auth", False))

    if not host:
        return False, "Missing required parameter 'host'"
    if not port:
        return False, "Missing required parameter 'port'"
    if not user:
        return False, "Missing required parameter 'user'"
    if not password:
        return False, "Missing required parameter 'password'"

    try:
        port = int(port)
    except (ValueError, TypeError):
        return False, f"Invalid 'port' value: {port}"

    scheme = "https" if use_https else "http"

    if legacy_auth:
        # Old-style auth (pre-1.13 or required by some servers e.g. Airsonic, LDAP)
        params = {
            "u": user,
            "p": password,
            "v": "1.13.0",
            "c": "network-watch",
        }
        auth_note = " (legacy auth)"
    else:
        # Modern token auth (recommended since API 1.13.0). Never send cleartext password.
        salt = secrets.token_hex(8)
        token = hashlib.md5((password + salt).encode("utf-8")).hexdigest()
        params = {
            "u": user,
            "t": token,
            "s": salt,
            "v": "1.16.1",
            "c": "network-watch",
        }
        auth_note = ""

    query = urllib.parse.urlencode(params)
    url = f"{scheme}://{host}:{port}/rest/ping.view?{query}"

    try:
        if use_https:
            # Relaxed TLS verification (many self-hosted Subsonic servers use self-signed certs)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            https_handler = urllib.request.HTTPSHandler(context=context)
            opener = urllib.request.build_opener(https_handler)
            response = opener.open(url, timeout=10)
        else:
            response = urllib.request.urlopen(url, timeout=10)

        # Subsonic returns HTTP 200 even for auth failures; status is in the XML body
        data = response.read().decode("utf-8", errors="replace")
        root = ET.fromstring(data)
        status = root.get("status")
        api_version = root.get("version", "?")

        if status == "ok":
            return (
                True,
                f"Subsonic server at {scheme}://{host}:{port} "
                f"responded OK (API v{api_version}){auth_note}",
            )
        else:
            # Extract error details if present (namespace http://subsonic.org/restapi)
            ns = {"sub": "http://subsonic.org/restapi"}
            error_elem = root.find(".//sub:error", ns)
            if error_elem is not None:
                code = error_elem.get("code", "?")
                msg = error_elem.get("message", "unknown error")
                return False, f"Subsonic error code {code}: {msg}"
            return False, f"Subsonic handshake failed with status={status}"

    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code} error from {scheme}://{host}:{port}: {e.reason}"
    except urllib.error.URLError as e:
        reason = str(e.reason) if e.reason else str(e)
        if "timed out" in reason.lower():
            return False, f"Connection to {scheme}://{host}:{port} timed out"
        if "connection refused" in reason.lower():
            return False, f"Connection refused to {scheme}://{host}:{port}"
        return False, f"Connection error to {scheme}://{host}:{port}: {reason}"
    except ET.ParseError as e:
        return False, f"Invalid XML response from Subsonic at {scheme}://{host}:{port}: {e}"
    except TimeoutError:
        return False, f"Connection to {scheme}://{host}:{port} timed out"
    except Exception as e:
        return False, f"Subsonic handshake failed: {e}"


def run_unknown(task: Task) -> tuple[bool, str]:
    """Placeholder for unknown/unsupported task types."""
    return False, f"Unsupported task type: '{task.type}'"


TASK_RUNNERS: dict[str, Callable[[Task], tuple[bool, str]]] = {
    "ping": run_ping,
    "http-get": run_http_get,
    "dns-resolve": run_dns_resolve,
    "ssh": run_ssh,
    "electrum": run_electrum,
    "stratum": run_stratum,
    "bitcoin": run_bitcoin,
    "lightning": run_lightning,
    "subsonic": run_subsonic,
}


# ------------------------------------------------------------------
# Core engine
# ------------------------------------------------------------------


def build_tasks(spec: dict[str, Any]) -> dict[str, Task]:
    """Build and validate tasks from a YAML-derived spec using Pydantic."""
    if not isinstance(spec, dict):
        raise TypeError(f"spec must be a dict (from yaml.safe_load), got {type(spec)}")

    tasks: dict[str, Task] = {}
    raw_tasks: Any = spec.get("tasks")
    if raw_tasks is None:
        raise TypeError("YAML file must contain a top-level 'tasks' key")
    if not isinstance(raw_tasks, list):
        raise TypeError(f"'tasks' must be a list, got {type(raw_tasks)}")

    for t in raw_tasks:
        try:
            task_spec = TaskSpec.model_validate(t)
            task = Task(task_spec)
        except ValidationError as e:
            raise click.ClickException(f"Invalid task definition: {e}") from e

        if task.name in tasks:
            raise click.ClickException(f"duplicate task name: {task.name}")
        tasks[task.name] = task

    for name, task in tasks.items():
        for d in task.depends_on:
            if d not in tasks:
                raise click.ClickException(f"task {name} depends on unknown task {d}")
    return tasks


def TaskNameRunner(task):
    """A wrapper around task.run to add the name to the output"""
    return task.name, *task.run()


def async_execute_all(
    tasks: dict[str, Task], console: Console | None = None, jobs: int = 1
) -> None:
    """Execute tasks in topological order with live progress indication."""
    if console is None:
        console = Console()

    indegree: dict[str, int] = {name: 0 for name in tasks}
    dependents: dict[str, list[str]] = {name: [] for name in tasks}
    for name, task in tasks.items():
        # we check that no names are repeated
        task.depends_on = list(set(task.depends_on))
        for dep in task.depends_on:
            indegree[name] += 1
            if dep in dependents:
                dependents[dep].append(name)
            else:
                # we check that every dependency corresponds to a valid task
                raise click.ClickException(f'Depedency "{dep}" is not a task')

    running = set()
    completed = []
    queue = deque([name for name, deg in indegree.items() if deg == 0])

    def propagate_children(name, success):
        completed.append(name)
        for child in dependents[name]:
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
            if not success:
                tasks[child].failed_ancestor = tasks[name].failed_ancestor

    with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as executor:
        # loop until there are not more elements in queue or executing
        while True:
            # elements in queue, execute them
            while queue:
                name = queue.popleft()
                task = tasks[name]
                # display task as running or skipped
                if task.failed_ancestor:
                    task.status = Status.SKIPPED
                    task.detail = f"Skipped due to failed ancestor '{task.failed_ancestor}'"
                    console.print()
                    console.print(f"[yellow][SKIPPED][/yellow] {task.name}: {task.detail}")
                    propagate_children(task.name, False)
                else:
                    task.status = Status.RUNNING
                    console.print()
                    console.print(
                        f"[bold cyan]▶ Running:[/bold cyan] [bold]{task.name}[/bold] "
                        f"(type=[magenta]{task.type}[/magenta])"
                    )
                    fut = executor.submit(TaskNameRunner, task)
                    running.add(fut)

            # if running is empty break
            if len(running) == 0:
                break

            # wait for the first future to finish
            done, running = concurrent.futures.wait(
                running, timeout=10, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for fut in done:
                name, success, message = fut.result()
                task = tasks[name]
                if success:
                    task.status = Status.SUCCESS
                    task.detail = message
                    console.print(f"[green][SUCCESS][/green] {task.name}: {message}")
                else:
                    task.status = Status.FAILED
                    task.detail = message
                    task.failed_ancestor = name  # himself
                    console.print(f"[red][FAILED][/red]  {task.name}: {message}")

                propagate_children(task.name, success)

    if len(completed) != len(tasks):
        raise click.ClickException("Dependency cycle detected in tasks")


@click.command()
@click.option(
    "--file",
    "-f",
    "path",
    required=False,
    type=click.Path(exists=True, dir_okay=False),
    help="YAML file with tasks (optional: defaults to Watch.yml in cwd, then $HOME/Watch.yml)",
)
@click.option(
    "--jobs",
    "-j",
    "jobs",
    required=False,
    type=click.IntRange(1, 10),
    help="Number of concurrent tasks at any given moment",
)
def main(path: str | None, jobs: int):
    if path is None:
        candidates = [
            os.path.join(os.getcwd(), "Watch.yml"),
            os.path.join(os.path.expanduser("~"), "Watch.yml"),
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                path = candidate
                break
        else:
            raise click.ClickException(
                "No --file provided and no Watch.yml found in current directory or $HOME"
            )

    try:
        with open(path) as fd:
            spec = yaml.safe_load(fd)
    except Exception as e:
        raise click.ClickException(f"failed to read YAML: {e}")

    try:
        tasks = build_tasks(spec)
    except (TypeError, ValueError, ValidationError) as e:
        raise click.ClickException(f"Invalid tasks data: {e}") from e
    except Exception as e:
        raise click.ClickException(f"failed to classify tasks: {e}")

    console = Console()
    try:
        async_execute_all(tasks, console, jobs)
    except Exception as e:
        raise click.ClickException(f"failed to execute tasks: {e}")

    # Rich Summary
    summary_table = Table(
        title="Execution Summary",
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
    )
    summary_table.add_column("Task", style="cyan", no_wrap=True)
    summary_table.add_column("Status", justify="center")
    summary_table.add_column("Description", style="dim")
    summary_table.add_column("Detail", style="dim")

    success_count = failed_count = skipped_count = 0
    for name, task in tasks.items():
        if task.status == Status.SUCCESS:
            status_text = Text("SUCCESS", style="bold green")
            success_count += 1
        elif task.status == Status.FAILED:
            status_text = Text("FAILED", style="bold red")
            failed_count += 1
        elif task.status == Status.SKIPPED:
            status_text = Text("SKIPPED", style="bold yellow")
            skipped_count += 1
        else:
            status_text = Text(task.status.value, style="dim")

        summary_table.add_row(name, status_text, task.description or "", task.detail or "")

    console.print(summary_table)
    total = len(tasks)
    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[green]{success_count} succeeded[/green], "
        f"[red]{failed_count} failed[/red], "
        f"[yellow]{skipped_count} skipped[/yellow] "
        f"(Total: {total})"
    )


if __name__ == "__main__":
    main()
