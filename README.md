# OpenVAS-MCP

[![Lint & Test](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/ci.yml)
[![Docker](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/docker.yml)
[![Integration tests](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/integration.yml)
[![Telemetry audit](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/telemetry-audit.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/telemetry-audit.yml)
![Coverage](docs/coverage-badge.svg)

A self-hosted MCP server that gives AI agents structured access to [OpenVAS / Greenbone](https://github.com/greenbone/openvas-scanner) vulnerability scanning — without sending your data anywhere.

OpenVAS has no native interface for AI agents. Most integrations require cloud connectivity or expose GVM credentials to every client. OpenVAS-MCP solves this:

- **Local-first.** Talks only to your GVM instance. No telemetry, no external calls — [verified by CI](.github/workflows/telemetry-audit.yml).
- **Credential isolation.** AI agents authenticate to the MCP server; the server holds the single GVM service account.
- **Thin bridge.** Returns structured scan data as-is. Analysis and reporting logic belong in the agent or a platform built on top.

See [docs/architecture.md](docs/architecture.md) for a full architecture diagram and design details.

## Quick start

### 0. Vibeinstall (optional, if you trust claude more than yourself)

Run in your terminal:

```bash
claude "install this, make no mistake."
```

If you prefer to stay in control, follow the manual setup below.

### 1. Get a GVM instance

Don't have one? Spin up the bundled Greenbone Community Edition stack:

```bash
docker compose -f docker/openvas/compose.yaml up -d
```

### 2. Connect an MCP client

#### stdio (Claude Desktop, Cursor, Windsurf, Cline, …)

**Requirements:** Python 3.10+

```bash
git clone https://github.com/CyberSecAuto-Labs/OpenVAS-MCP
cd OpenVAS-MCP
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Add to `mcpServers` in your client config file:

```json
{
  "mcpServers": {
    "openvas": {
      "command": "/path/to/.venv/bin/python",  // ← edit this to your venv path
      "args": ["-m", "openvas_mcp"],
      "env": { "GVM_PASSWORD": "secret" }  // ← edit this to your GVM password
    }
  }
}
```

Config file locations:

| Client | Path |
|---|---|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline / Roo Code | via the MCP panel in the VS Code extension |

#### HTTP/SSE (networked agents)

**Requirements:** Docker

Download the compose files from the [latest release](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/releases/latest) and run:

```bash
# GVM running locally via Unix socket
MCP_API_KEYS="supersecrettoken:my-agent" GVM_PASSWORD=secret docker compose up

# GVM on a remote host via TCP
MCP_API_KEYS="supersecrettoken:my-agent" GVM_HOST=192.168.1.10 GVM_PASSWORD=secret docker compose up
```

> [!NOTE]
> `MCP_API_KEYS` is a comma-separated list of `token:name` pairs sent as a Bearer token by the MCP client. Multiple clients: `"tok1:agent1,tok2:agent2"`. Pass `MCP_ALLOW_UNAUTHENTICATED=1` instead to skip auth on a trusted network.

Point your MCP client at the server:

```json
{
  "mcpServers": {
    "openvas": {
      "url": "http://your-server:8000/sse",  // ← edit this to your server address
      "headers": {
        "Authorization": "Bearer supersecrettoken"  // ← your MCP_API_KEYS token
      }
    }
  }
}
```

> [!WARNING]
> Plain TCP connections (`GVM_HOST` set, `GVM_TLS` unset) send GVM credentials unencrypted. Use `GVM_TLS=1` or a Unix socket for anything beyond local dev.

### All-in-one dev setup

Greenbone Community Edition + MCP server from source in one go:

```bash
# Start the Greenbone stack
docker compose -f docker/openvas/compose.yaml up -d

# Start the MCP server, connected via gvmd socket
GVM_PASSWORD=secret docker compose -f compose.yaml -f compose.override.yaml up --build
```

> [!TIP]
> See [`compose.override.yaml`](compose.override.yaml) for how the socket volume is mounted.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `GVM_PASSWORD` | — | GVM password (required) |
| `GVM_SOCKET_PATH` | `/run/gvmd/gvmd.sock` | Unix socket path (default connection) |
| `GVM_HOST` | — | Connect via TCP instead of socket (IPv4 and IPv6) |
| `MCP_TRANSPORT` | `stdio` | `stdio`, `sse`, or `streamable-http` |
| `MCP_API_KEYS` | — | Bearer API keys for HTTP transport auth (`token:name,...`) |

See [docs/configuration.md](docs/configuration.md) for the full reference, including TLS options, policy file, scan limits, and logging.

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

## Release integrity

Every release image is:

- **Signed** with [cosign](https://github.com/sigstore/cosign) keyless OIDC signing — no long-lived key to compromise.
- **SBOM attached** — a CycloneDX JSON bill of materials is attached to each GitHub Release for vulnerability scanning and compliance audits.
- **Telemetry-audited** — the [`telemetry-audit` workflow](.github/workflows/telemetry-audit.yml) runs the server in a network-isolated container (`--network=none`) on every push and PR, asserting no unexpected outbound connections.

Verify the image signature before running:

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/cybersecauto-labs/openvas-mcp:<version>
```

## Docs

- [docs/architecture.md](docs/architecture.md) — architecture diagram, component overview, and transport details
- [docs/configuration.md](docs/configuration.md) — full environment variable reference, TLS, policy file, scan limits, logging
- [docs/design.md](docs/design.md) — design decisions and known limitations
- [docs/ci.md](docs/ci.md) — CI workflows, guarantees, and tradeoffs

## License

[Apache 2.0](LICENSE)
