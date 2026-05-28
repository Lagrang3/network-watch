#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = ["rich", "click", "pyyaml==6.0.3", "pydantic>=2", "pyln-proto==26.04.1"]
# ///

from __future__ import annotations

from typing import Any, Dict, List

from pydantic import BaseModel, Field, ValidationError, ConfigDict
from enum import Enum

from rich.console import Console
from rich.text import Text
from rich.table import Table
from rich import box
import click
import yaml
import subprocess
import socket
import ssl
import json
import os

# Lightning - using the high-level API from pyln-proto v26.04.1
try:
    from pyln.proto.wire import connect as lightning_connect
    from pyln.proto.primitives import PrivateKey
except ImportError:
    lightning_connect = None
    PrivateKey = None


class TaskSpec(BaseModel):
    """Pydantic model for validating a single task entry from YAML."""
    name: str
    type: str
    depends_on: List[str] = Field(default_factory=list)
    description: str = ""

    model_config = ConfigDict(extra="allow")


class Status(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    SUCCESS = "Success"
    FAILED = "Failed"
    SKIPPED = "Skipped"


class Task:
    def __init__(self, spec: TaskSpec):
        self.name: str = spec.name
        self.type: str = spec.type
        self.depends_on: List[str] = spec.depends_on
        self.description: str = spec.description or ""

        self.params: Dict[str, Any] = {
            k: v for k, v in spec.model_dump().items()
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
# Task Runners
# ------------------------------------------------------------------

def run_ping(task: Task) -> tuple[bool, str]:
    target = task.params.get("target")
    if not target:
        return False, "Missing required parameter 'target'"

    cmd = ["ping", "-c", "4", "-W", "2", target]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=15)
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
        error_msg = output.splitlines()[-1] if output else f"Ping failed with exit code {result.returncode}"
        return False, f"Ping to {target} failed: {error_msg}"


def run_http_get(task: Task) -> tuple[bool, str]:
    url = task.params.get("url")
    if not url:
        return False, "Missing required parameter 'url'"

    cmd = ["curl", "-sS", "-I", "--max-time", "10", url]

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=15)
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
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=10)
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
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=15)
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

    return False, f"SSH host key mismatch on {target}:{port}. Expected identity not found in scan results."


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
                "params": ["network-watch", "1.4"]
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
            return True, f"Electrum server at {host}:{port}{tls_note} responded: {version}"

    except socket.timeout:
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
                "params": ["network-watch/1.0"]
            }
            message = json.dumps(request) + "\n"
            sock.sendall(message.encode("utf-8"))

            data = _wait_for_jsonrpc_response(sock, request_id, host, port)

            error = data.get("error")
            if error is not None:
                return False, f"Stratum server error: {error}"

            return True, f"Stratum server at {host}:{port} responded successfully"

    except socket.timeout:
        return False, f"Connection to {host}:{port} timed out"
    except ConnectionRefusedError:
        return False, f"Connection refused to {host}:{port}"
    except json.JSONDecodeError:
        return False, f"Invalid JSON response received from {host}:{port}"
    except RuntimeError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Failed to connect to Stratum server: {e}"


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
        return False, "Missing required parameter 'node_id' (33-byte compressed public key in hex)"

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

    except socket.timeout:
        return False, f"Connection to {host}:{port} timed out"
    except ConnectionRefusedError:
        return False, f"Connection refused to {host}:{port}"
    except Exception as e:
        return False, f"Lightning handshake failed: {e}"


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
    "lightning": run_lightning,
}


# ------------------------------------------------------------------
# Core engine
# ------------------------------------------------------------------

def build_tasks(spec: Dict[str, Any]) -> Dict[str, Task]:
    """Build and validate tasks from a YAML-derived spec using Pydantic."""
    if not isinstance(spec, dict):
        raise TypeError(f"spec must be a dict (from yaml.safe_load), got {type(spec)}")

    tasks: Dict[str, Task] = {}
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


def topo_order(tasks: Dict[str, Task]) -> List[Task]:
    """Return tasks in topological order using Kahn's algorithm."""
    from collections import deque

    graph: Dict[str, List[str]] = {name: [] for name in tasks}
    indegree: Dict[str, int] = {name: 0 for name in tasks}

    for name, task in tasks.items():
        for dep in task.depends_on:
            if dep in graph:
                graph[dep].append(name)
                indegree[name] += 1

    queue = deque([name for name, deg in indegree.items() if deg == 0])
    order: List[Task] = []

    while queue:
        name = queue.popleft()
        order.append(tasks[name])
        for neighbor in graph[name]:
            indegree[neighbor] -= 1
            if indegree[neighbor] == 0:
                queue.append(neighbor)

    if len(order) != len(tasks):
        raise click.ClickException("Dependency cycle detected in tasks")

    return order


def execute_all(tasks: Dict[str, Task], console: Console | None = None) -> None:
    """Execute tasks in topological order with live progress indication."""
    if console is None:
        console = Console()

    ordered = topo_order(tasks)

    dependents: Dict[str, list[str]] = {name: [] for name in tasks}
    for name, task in tasks.items():
        for dep in task.depends_on:
            if dep in dependents:
                dependents[dep].append(name)

    failed_ancestors: set[str] = set()

    for task in ordered:
        if any(dep in failed_ancestors for dep in task.depends_on):
            task.status = Status.SKIPPED
            task.detail = "Skipped due to failed dependency"
            console.print(f"[yellow][SKIPPED][/yellow] {task.name}: {task.detail}")
            continue

        console.print()
        console.print(f"[bold cyan]▶ Running:[/bold cyan] [bold]{task.name}[/bold] "
                      f"(type=[magenta]{task.type}[/magenta])")

        task.status = Status.RUNNING
        success, message = task.run()

        if success:
            task.status = Status.SUCCESS
            console.print(f"[green][SUCCESS][/green] {task.name}: {message}")
        else:
            task.status = Status.FAILED
            task.detail = message
            console.print(f"[red][FAILED][/red]  {task.name}: {message}")

            failed_ancestors.add(task.name)
            queue = list(dependents.get(task.name, []))
            while queue:
                dep_name = queue.pop(0)
                if dep_name not in failed_ancestors:
                    failed_ancestors.add(dep_name)
                    tasks[dep_name].status = Status.SKIPPED
                    tasks[dep_name].detail = f"Skipped due to failed ancestor '{task.name}'"
                    queue.extend(dependents.get(dep_name, []))


@click.command()
@click.option("--file", "-f", "path", required=True,
              type=click.Path(exists=True, dir_okay=False),
              help="YAML file with tasks")
def main(path: str):
    try:
        with open(path, "r") as fd:
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
        execute_all(tasks, console)
    except Exception as e:
        raise click.ClickException(f"failed to execute tasks: {e}")

    # Rich Summary
    summary_table = Table(title="Execution Summary", show_header=True,
                          header_style="bold magenta", box=box.ROUNDED)
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
    console.print(f"\n[bold]Summary:[/bold] "
                  f"[green]{success_count} succeeded[/green], "
                  f"[red]{failed_count} failed[/red], "
                  f"[yellow]{skipped_count} skipped[/yellow] "
                  f"(Total: {total})")


if __name__ == "__main__":
    main()
