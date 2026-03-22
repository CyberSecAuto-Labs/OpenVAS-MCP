# OpenVAS-MCP

An MCP (Model Context Protocol) server that bridges AI agents to [OpenVAS / Greenbone Vulnerability Management](https://www.greenbone.net/). It translates MCP tool calls into GMP (Greenbone Management Protocol) API calls, returning structured results to the AI agent.

```
AI agent → MCP client → OpenVAS MCP server → Greenbone/GMP API → scanning infrastructure
```

## Requirements

- Python 3.10+
- A running OpenVAS / Greenbone instance accessible via Unix socket or TLS

## Setup

```bash
git clone https://github.com/your-org/OpenVAS-MCP.git
cd OpenVAS-MCP
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuration

The server is configured via environment variables:

| Variable | Default | Description |
|---|---|---|
| `GVM_SOCKET_PATH` | `/run/gvmd/gvmd.sock` | Path to gvmd Unix socket |
| `GVM_HOST` | — | If set, connect via TLS instead of socket |
| `GVM_PORT` | `9393` | TLS port (only used when `GVM_HOST` is set) |
| `GVM_USERNAME` | `admin` | GVM username |
| `GVM_PASSWORD` | — | GVM password (required) |

## Running

```bash
# Unix socket (default)
GVM_PASSWORD=secret python -m openvas_mcp

# TLS connection
GVM_HOST=192.168.1.10 GVM_PORT=9393 GVM_USERNAME=admin GVM_PASSWORD=secret python -m openvas_mcp
```

## Claude Desktop integration

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "openvas": {
      "command": "/path/to/.venv/bin/python",
      "args": ["-m", "openvas_mcp"],
      "env": {
        "GVM_PASSWORD": "secret"
      }
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
| `get_scan_status` | Check status and progress of a running scan |
| `fetch_scan_results` | Retrieve findings from a completed scan, optionally filtered by minimum severity |

## Example workflow

Once connected, an AI agent can run a full scan with natural language:

> "Scan 192.168.1.0/24 for vulnerabilities and show me anything with severity above 7."

The agent will call:
1. `create_target` — registers the subnet as a scan target
2. `start_scan` — launches the scan using the Full and Fast config
3. `get_scan_status` — polls until the scan completes
4. `fetch_scan_results(min_severity=7.0)` — returns high/critical findings

## License

MIT
