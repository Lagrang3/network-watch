# Network Watch

A lightweight, dependency-aware task runner for network and infrastructure validation tasks.

It reads a YAML file defining tasks, executes them in the correct order (respecting dependencies), and provides clear live feedback plus a rich summary at the end.

## Features

- **Dependency-aware execution** — Tasks run in topological order based on `depends_on`.
- **Failure propagation** — If a task fails, all tasks that depend on it (directly or indirectly) are automatically marked as **SKIPPED**.
- **Live progress** — Clear indication of which task is currently running.
- **Rich summary** — A nicely formatted table at the end showing status, description, and details.
- **Validation** — Tasks are validated using Pydantic before execution.
- **Extensible** — Easy to add new task types.

## Supported Task Types

| Type          | Description                                      | Required Parameters               |
|---------------|--------------------------------------------------|-----------------------------------|
| `ping`        | Checks network reachability using `ping`         | `target`                          |
| `http-get`    | Verifies HTTP server response using `curl`       | `url`                             |
| `dns-resolve` | Performs DNS lookup using the `host` command     | `host`                            |
| `ssh`         | Checks SSH port reachability + host identity     | `target`, `identity`              |
| `electrum`    | Connects to an Electrum server (TLS optional)    | `host`, `port`                    |
| `stratum`     | Performs Stratum (Bitcoin mining) handshake      | `host`, `port`                    |
| `lightning`   | Connects to a Lightning node and reports node ID | `host`, `port`, `node_id`         |

## Task Details

### ping

**Description:** Checks network reachability to a host or IP address.

**Parameters:**
- `target` (required): IP address or hostname to ping

**Notes:**
- Uses the command `ping -c 4 -W 2 <target>`.
- Succeeds if the host responds to at least one of the four packets.
- `target` can be either an IP address or a hostname.

### http-get

**Description:** Verifies that an HTTP/HTTPS server is responding correctly.

**Parameters:**
- `url` (required): Full URL to check (must include `http://` or `https://`)

**Notes:**
- Performs a lightweight HEAD request using `curl`.
- Considered successful if the server returns a 2xx or 3xx status code.
- Timeouts after 10 seconds.

### dns-resolve

**Description:** Performs a DNS lookup for a hostname (or reverse lookup for an IP).

**Parameters:**
- `host` (required): Domain name or IP address to resolve

**Notes:**
- Uses the standard `host` command-line tool.
- Succeeds if DNS resolution returns at least one result.
- Works for both forward lookups (domain → IP) and reverse lookups (IP → domain).

### ssh

**Description:** Checks that an SSH server is reachable on the specified port and that its public host key matches the provided `identity`.

**Parameters:**
- `target` (required): Hostname or IP address of the SSH server
- `identity` (required): The expected SSH host public key (e.g. `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...`)
- `port` (optional): SSH port (defaults to 22)

**How to obtain the identity from the command line:**

```bash
# Recommended: Get the ed25519 host key (most common modern type)
ssh-keyscan -t ed25519 -H <hostname-or-ip>

# Clean output — only the key part (recommended for your config)
ssh-keyscan -t ed25519 -H <hostname-or-ip> 2>/dev/null | awk '{print $2, $3}'
```

**With a custom port:**

```bash
ssh-keyscan -p 2222 -t ed25519 -H 192.168.1.50
```

### electrum

**Description:** Connects to an Electrum server and performs a protocol handshake (TLS is optional).

**Parameters:**
- `host` (required): Hostname or IP address of the Electrum server
- `port` (required): Port number
- `TLS` (optional, default: `false`): If set to `true`, the connection will be made over TLS. If `false` or omitted, a plain text connection is used.

**Notes:**
- When `TLS: true`, a TLS connection is established (with relaxed certificate verification, as many Electrum servers use self-signed certificates).
- When `TLS` is missing or `false`, a plain TCP connection is used.
- Performs a standard `server.version` handshake.
- Common ports: 50002 (TLS) or 50001 (plain text).

### stratum

**Description:** Performs a basic Stratum protocol handshake (used by Bitcoin mining pools) over plain TCP.

**Parameters:**
- `host` (required): Hostname or IP address of the Stratum server
- `port` (required): Port number

**Notes:**
- Always uses plain TCP.
- Uses the `mining.subscribe` method for the handshake.
- Common ports: 3333, 4444, etc.

### lightning

**Description:** Connects to a Lightning node using the Noise protocol handshake and reports the remote node's ID on success.

**Parameters:**
- `host` (required): Hostname or IP address of the Lightning node
- `port` (required): Port number (usually 9735)
- `node_id` (required): The 33-byte compressed public key of the Lightning node in hex (66 characters)

**Notes:**
- Uses `pyln-proto` to perform the authenticated Lightning handshake.
- On success, the remote node ID is included in the execution summary.
- Connection failures (refused, timeout, or handshake errors) are reported as failures.

## Usage

The `-f` / `--file` argument is optional. If omitted, the CLI automatically looks for a `Watch.yml` file first in the current working directory, then falls back to `$HOME/Watch.yml`. If neither exists (or cannot be read), the command fails with a clear error.

```bash
uv run --script watch.py            # uses Watch.yml from cwd or $HOME
uv run --script watch.py -f tasks.yml
```

Or directly:

```bash
python watch.py
python watch.py -f tasks.yml
```

## Example YAML

```yaml
tasks:
  - name: lan-ping
    type: ping
    target: 192.168.1.1
    description: "Check local gateway reachability"

  - name: public-dns
    type: dns-resolve
    host: example.com
    depends_on:
      - lan-ping
    description: "Verify public DNS resolution"

  - name: web-check
    type: http-get
    url: https://example.com
    depends_on:
      - public-dns

  - name: bastion-ssh
    type: ssh
    target: 10.0.0.5
    identity: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
    port: 22
    depends_on:
      - lan-ping
    description: "Verify SSH host key on bastion"

  - name: electrum-mainnet
    type: electrum
    host: electrum.blockstream.info
    port: 50002
    TLS: true
    depends_on:
      - lan-ping
    description: "Check mainnet Electrum server over TLS"

  - name: mining-pool
    type: stratum
    host: pool.example.com
    port: 3333
    depends_on:
      - lan-ping
    description: "Check stratum mining pool"

  - name: lnd-node
    type: lightning
    host: 203.0.113.50
    port: 9735
    node_id: 03e2a5b4c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5
    depends_on:
      - lan-ping
    description: "Verify Lightning node reachability"
```

## Execution Behavior

- Tasks are executed in **topological order** (dependencies first).
- If a task fails, all downstream dependent tasks are automatically **skipped**.
- The final output includes:
  - Live progress during execution
  - A rich summary table showing:
    - Task name
    - Status (`SUCCESS`, `FAILED`, or `SKIPPED`)
    - Description (if provided)
    - Detail / result message

## Requirements

- Python 3.12+
- `uv` (recommended) or pip

Dependencies are declared at the top of `watch.py` using PEP 723 inline script metadata and will be installed automatically when using `uv run --script`.

## Adding New Task Types

New task types can be added by implementing a function with this signature:

```python
def run_my_task(task: Task) -> tuple[bool, str]:
    ...
```

and registering it in the `TASK_RUNNERS` dictionary inside `watch.py`.

