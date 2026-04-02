# Configuration reference

All configuration is read from environment variables at startup. Invalid values cause the server to exit with a descriptive error message.

## GVM connection

| Variable | Default | Description |
|---|---|---|
| `GVM_SOCKET_PATH` | `/run/gvmd/gvmd.sock` | Path to gvmd Unix socket (used when `GVM_HOST` is not set) |
| `GVM_HOST` | — | If set, connect via TCP instead of socket (IPv4 and IPv6 supported) |
| `GVM_PORT` | `9390` | Port (used when `GVM_HOST` is set) |
| `GVM_TLS` | — | Set to `1` to use TLS with `GVM_HOST` |
| `GVM_TLS_CAFILE` | — | Path to CA certificate for self-signed GVM certs (requires `GVM_TLS=1`) |
| `GVM_TLS_NO_VERIFY` | — | Set to `1` to skip TLS certificate verification — insecure, not for production |
| `GVM_USERNAME` | `admin` | GVM username — a dedicated least-privilege account is recommended |
| `GVM_PASSWORD` | — | GVM password (required) |

> Plain TCP connections (`GVM_HOST` set, `GVM_TLS` unset) send GVM credentials unencrypted. Use `GVM_TLS=1` or a Unix socket for production deployments.

## MCP server

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | Transport: `stdio`, `sse`, or `streamable-http` |
| `MCP_HOST` | `127.0.0.1` | Bind address for HTTP transports |
| `MCP_PORT` | `8000` | Bind port for HTTP transports |
| `MCP_API_KEYS` | — | Bearer API keys for HTTP transport auth, as `token:name` pairs separated by commas (e.g. `tok1:agent,tok2:readonly`) |
| `MCP_ALLOW_UNAUTHENTICATED` | — | Set to `1` to run HTTP transport without API key authentication — development only |
| `MCP_POLICY_FILE` | — | Path to YAML authorization policy file; if unset, all authenticated clients have full access. Missing file = startup failure. |

## Scan behaviour

| Variable | Default | Description |
|---|---|---|
| `GVM_SCAN_POLL_TIMEOUT` | `3600` | Maximum seconds `get_scan_status` will poll before returning a `timeout` error. Must be a positive integer. |
| `GVM_REPORT_MAX_RESULTS` | `2000` | Maximum results returned by `fetch_scan_results`. `0` = unlimited. Truncated responses include `{"truncated": true, "cap": N}`. |

## Logging

| Variable | Default | Description |
|---|---|---|
| `LOG_LEVEL` | `INFO` | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |

All log output goes to stderr as structured JSON (one object per line). The stdio transport uses stdout as the JSON-RPC channel — nothing is written there.

## Policy file

When `MCP_POLICY_FILE` is set, the server loads a YAML policy on startup that controls per-client access. See [`examples/policy.yaml`](../examples/policy.yaml) for a documented example.

Capabilities:
- **Tool allow/deny** — restrict which MCP tools a client can call
- **CIDR target restriction** — limit which hosts a client can scan; non-CIDR entries are treated as fnmatch hostname patterns (e.g. `*.internal`)
- **Concurrent scan limit** — cap the number of simultaneously running scans per client (counted GVM-globally)

See [architecture.md](architecture.md) for the full auth and policy model.
