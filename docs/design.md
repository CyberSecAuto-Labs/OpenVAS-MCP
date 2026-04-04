# Design decisions

## Single GVM service account

The MCP server authenticates to GVM using one dedicated service account. AI agents and end users never hold GVM credentials — they authenticate to the MCP server itself. This isolates credential exposure to a single, auditable surface.

## Protocol bridge only

The server translates MCP tool calls into GMP operations and returns structured results. It implements no vulnerability analysis, prioritization, or remediation logic. That belongs in the agent or a platform built on top.

## stderr for all diagnostics

The stdio transport uses stdout as the JSON-RPC channel. Any byte written to stdout outside of the MCP framing corrupts the stream. All logging goes to stderr via the structured JSON logger.

## Structured error returns

Tools return `{"error": true, "code": "...", "message": "..."}` rather than raising exceptions into the MCP framework. This gives the calling agent a machine-readable error it can act on, rather than an opaque protocol-level failure.

## API key authentication (HTTP transport)

Bearer token authentication is implemented as a pure ASGI middleware rather than `BaseHTTPMiddleware`. This is intentional: `BaseHTTPMiddleware` buffers response bodies, which breaks SSE streaming. The pure ASGI approach passes the scope/receive/send triple through without buffering.

API keys are loaded from `MCP_API_KEYS` at startup. Each token maps to a client name used in logs and policy lookups. There is no key rotation API — tokens are managed by restarting the server with an updated env var. JWT support is deferred to a future phase if expiry or richer metadata is needed.

The stdio transport bypasses auth entirely — it is a trusted local process model, consistent with how MCP clients like Claude Desktop work.

## Configuration-driven policy engine

Authorization policy lives in a YAML file (`MCP_POLICY_FILE`) rather than code or a database. YAML is expressive enough to define per-client tool lists and CIDR ranges without requiring a running service or migration tooling. Policy takes effect on server restart.

The policy engine is deny-by-default at the per-client level: if a `clients` block exists and a client is not listed, they fall back to the `default` block. If no `default` block is defined, the built-in default permits everything — this keeps the server usable without a policy file for trusted deployments.

CIDR enforcement happens at `create_target` time, where hosts are explicitly defined. It does not re-check hosts at `start_scan` time (which only receives a target UUID) — this is a known limitation documented below.

## Minimal runtime dependencies

`python-gvm` for GMP, `mcp[cli]` for the MCP server, `pyyaml` for policy files. No framework beyond what the protocol requires.

---

# Known limitations

## Policy & authorization

- **CIDR policy enforced at target creation only.** The `start_scan` tool takes a `target_id`, not a host list. CIDR policy is not re-validated at scan time — a target created before a more restrictive policy was deployed can still be scanned. Enforce policy at `create_target` time and manage target lifecycle accordingly.

- **Hostnames not matched by CIDR rules.** When a client has explicit CIDR restrictions, hostname targets (e.g. `myhost.example.com`) are denied — they cannot be resolved to an IP at policy check time. Use IP addresses or CIDR ranges in targets when CIDR policy is active.

- **No API key expiry.** API keys are static strings with no built-in rotation or TTL. Revoke a key by removing it from `MCP_API_KEYS` and restarting the server.

## Scanning

- **No scan scheduling.** Tasks must be triggered explicitly via `start_scan`. There is no recurring or time-based scheduling.

- **`get_scan_status` polls on a fixed interval.** The tool polls every 10 seconds with no push notification or webhook mechanism from GVM. It stops and returns a `"timeout"` error once the configurable deadline (`GVM_SCAN_POLL_TIMEOUT`, default 3600 s) is reached; call the tool again to resume monitoring.

## Configuration & deployment

- **Hardcoded default UUIDs.** The default scan config and scanner UUIDs are hardcoded constants matching a standard [Greenbone Community Edition](https://greenbone.github.io/docs/latest/22.4/container/index.html#download) install. Non-standard deployments must pass explicit UUIDs.

- **Single GVM instance.** The server connects to one GVM instance, configured at startup. Multi-instance routing is not supported.

> [!NOTE]
> For CI-specific limitations and tradeoffs (telemetry audit coverage, GHCR mirror, QEMU emulation), see [ci.md](ci.md).
