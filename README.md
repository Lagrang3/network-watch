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

| Type          | Description                                      | Required Parameters          |
|---------------|--------------------------------------------------|------------------------------|
| `ping`        | Checks network reachability using `ping`         | `target`                     |
| `http-get`    | Verifies HTTP server response using `curl`       | `url`                        |
| `dns-resolve` | Performs DNS lookup using the `host` command     | `host`                       |
| `ssh`         | Checks SSH port reachability + host identity     | `target`, `identity`         |

## Usage

```bash
uv run --script watch.py -f tasks.yml
```

Or directly:

```bash
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

