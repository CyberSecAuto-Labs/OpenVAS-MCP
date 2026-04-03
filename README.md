# OpenVAS-MCP

[![Lint & Test](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/ci.yml)
[![Docker](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/docker.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/docker.yml)
[![Integration tests](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/integration.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/integration.yml)
[![Telemetry audit](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/telemetry-audit.yml/badge.svg?branch=main)](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/actions/workflows/telemetry-audit.yml)
![Coverage](docs/coverage-badge.svg)

A self-hosted MCP server that gives AI agents structured access to [OpenVAS / Greenbone](https://github.com/greenbone/openvas-scanner) vulnerability scanning — without sending your data anywhere.

## Why this exists

OpenVAS has no native interface for AI agents. Most integrations require cloud connectivity or expose GVM credentials to every client. OpenVAS-MCP solves this:

- **Local-first.** Talks only to your GVM instance. No telemetry, no external calls — [verified by CI](.github/workflows/telemetry-audit.yml).
- **Credential isolation.** AI agents authenticate to the MCP server; the server holds the single GVM service account.
- **Thin bridge.** Returns structured scan data as-is. Analysis and reporting logic belong in the agent or a platform built on top.

## Architecture

```
AI agent → MCP client → OpenVAS MCP server → GMP API → OpenVAS / Greenbone
```

Supports stdio (local, zero-config) and HTTP/SSE transports. See [docs/architecture.md](docs/architecture.md) for details.

## Quick start

**Requirements:** Python 3.10+ or Docker, a running OpenVAS / Greenbone instance.

### Local / Claude Desktop (stdio)

```bash
git clone https://github.com/CyberSecAuto-Labs/OpenVAS-MCP
cd OpenVAS-MCP
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
GVM_PASSWORD=secret python -m openvas_mcp
```

For any MCP client that supports stdio (Claude Desktop, Cursor, Windsurf, Cline, Continue, Zed, …), add to `mcpServers` in your config:

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

### Networked deployment (SSE)

**Using a published release** (recommended for production):

Download the compose files from the [latest release](https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/releases/latest) and run:

```bash
# Socket (OpenVAS running locally) — with API key auth
MCP_API_KEYS="supersecrettoken:my-agent" GVM_PASSWORD=secret docker compose up

# TCP — with API key auth
MCP_API_KEYS="supersecrettoken:my-agent" GVM_HOST=192.168.1.10 GVM_PASSWORD=secret docker compose up
```

- `MCP_API_KEYS` is a comma-separated list of `token:name` pairs. The `token` is the secret your MCP client will send as a Bearer token; the `name` is a label used in logs and policy lookups. Multiple clients: `"tok1:agent1,tok2:agent2"`.

- Pass `MCP_ALLOW_UNAUTHENTICATED=1` instead of `MCP_API_KEYS` if you want to skip auth on a trusted network.

This pulls `ghcr.io/cybersecauto-labs/openvas-mcp:<version>` — a pinned, signed image. To verify the signature before running:

```bash
cosign verify \
  --certificate-identity-regexp "https://github.com/CyberSecAuto-Labs/OpenVAS-MCP/.github/workflows/release.yml@refs/tags/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/cybersecauto-labs/openvas-mcp:<version>
```

**Building from source** (for development or unreleased changes):

```bash
git clone https://github.com/CyberSecAuto-Labs/OpenVAS-MCP
cd OpenVAS-MCP
GVM_PASSWORD=secret docker compose up --build
```

The server listens on `127.0.0.1:8000` using SSE transport.

By default the HTTP server requires an API key. Set one with `MCP_API_KEYS`, or opt out explicitly for trusted networks:

```bash
# With authentication (recommended)
MCP_API_KEYS="supersecrettoken:my-agent" GVM_PASSWORD=secret docker compose up --build

# Without authentication (trusted network only)
MCP_ALLOW_UNAUTHENTICATED=1 GVM_PASSWORD=secret docker compose up --build
```

See the published release section above for details on the `MCP_API_KEYS` format.

**All-in-one dev setup** (Greenbone Community Edition + MCP server):

```bash
# Start the Greenbone stack
docker compose -f docker/openvas/compose.yaml up -d

# Start the MCP server, connected via gvmd socket
GVM_PASSWORD=secret docker compose -f compose.yaml -f compose.override.yaml up
```

See [`compose.override.yaml`](compose.override.yaml) for how the socket volume is mounted.

> **Note:** Plain TCP connections (`GVM_HOST` set, `GVM_TLS` unset) send GVM credentials unencrypted. Use `GVM_TLS=1` or a Unix socket for anything beyond local dev.

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

- **Signed** with [cosign](https://github.com/sigstore/cosign) keyless OIDC signing — no long-lived key to compromise. Verify with `cosign verify` as shown in the quickstart.
- **SBOM attached** — a CycloneDX JSON bill of materials is attached to each GitHub Release for vulnerability scanning and compliance audits.
- **Telemetry-audited** — the [`telemetry-audit` workflow](.github/workflows/telemetry-audit.yml) runs the server in a network-isolated container (`--network=none`) on every push and PR, asserting no unexpected outbound connections.

## Notes

- See [docs/design.md](docs/design.md) for design decisions and known limitations.
- See [docs/ci.md](docs/ci.md) for a description of each CI workflow, the guarantees it provides, and the tradeoffs made.

## License

Apache 2.0
