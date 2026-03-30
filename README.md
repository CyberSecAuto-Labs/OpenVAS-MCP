# OpenVAS-MCP

![Coverage](docs/coverage-badge.svg)

A self-hosted MCP server that gives AI agents structured access to [OpenVAS / Greenbone](https://github.com/greenbone/openvas-scanner) vulnerability scanning — without sending your data anywhere.

## Why this exists

OpenVAS has no native interface for AI agents. Most integrations require cloud connectivity or expose GVM credentials to every client. OpenVAS-MCP solves this:

- **Local-first.** Talks only to your GVM instance. No telemetry, no external calls.
- **Credential isolation.** AI agents authenticate to the MCP server; the server holds the single GVM service account.
- **Thin bridge.** Returns structured scan data as-is. Analysis and reporting logic belong in the agent or a platform built on top.

## Architecture

```
AI agent → MCP client → OpenVAS MCP server → GMP API → OpenVAS / Greenbone
```

Supports stdio (local, zero-config) and HTTP/SSE transports. See [docs/architecture.md](docs/architecture.md) for details.

## Quick start

**Requirements:** Python 3.10+, a running OpenVAS / Greenbone instance.

```bash
git clone https://github.com/CyberSecAuto-Labs/OpenVAS-MCP
cd OpenVAS-MCP
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
GVM_PASSWORD=secret python -m openvas_mcp
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `GVM_SOCKET_PATH` | `/run/gvmd/gvmd.sock` | Path to gvmd Unix socket |
| `GVM_HOST` | — | If set, connect via TCP instead of socket |
| `GVM_PORT` | `9390` | Port (used when `GVM_HOST` is set) |
| `GVM_TLS` | — | Set to `1` to use TLS with `GVM_HOST` |
| `GVM_USERNAME` | `admin` | GVM username |
| `GVM_PASSWORD` | — | GVM password (required) |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

## Claude Desktop integration

```json
{
  "mcpServers": {
    "openvas": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "openvas_mcp"],
      "env": { "GVM_PASSWORD": "secret" }
    }
  }
}
```

## Available tools

| Tool | Description |
|---|---|
| `list_targets` | Return all scan targets |
| `create_target` | Create a target with specified hosts/CIDRs |
| `list_tasks` | Return all scan tasks |
| `start_scan` | Create and start a scan against a target |
| `get_scan_status` | Poll status and progress of a running scan |
| `fetch_scan_results` | Retrieve findings, optionally filtered by minimum severity |

**Example:** `"Scan 192.168.1.0/24 and show me anything above severity 7"` — the agent calls `create_target` → `start_scan` → `get_scan_status` → `fetch_scan_results(min_severity=7.0)`.

## Notes

See [docs/design.md](docs/design.md) for design decisions and known limitations.

## License

Apache 2.0
