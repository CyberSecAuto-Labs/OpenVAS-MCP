# Design decisions

## Single GVM service account

The MCP server authenticates to GVM using one dedicated service account. AI agents and end users never hold GVM credentials — they authenticate to the MCP server itself. This isolates credential exposure to a single, auditable surface.

## Protocol bridge only

The server translates MCP tool calls into GMP operations and returns structured results. It implements no vulnerability analysis, prioritization, or remediation logic. That belongs in the agent or a platform built on top.

## stderr for all diagnostics

The stdio transport uses stdout as the JSON-RPC channel. Any byte written to stdout outside of the MCP framing corrupts the stream. All logging goes to stderr via the structured JSON logger.

## Structured error returns

Tools return `{"error": true, "code": "...", "message": "..."}` rather than raising exceptions into the MCP framework. This gives the calling agent a machine-readable error it can act on, rather than an opaque protocol-level failure.

## Minimal runtime dependencies

`python-gvm` for GMP, `mcp[cli]` for the MCP server, `lxml` for XML parsing. No framework beyond what the protocol requires.

---

# Current limitations

- **No HTTP/SSE authentication.** The HTTP/SSE transport has no auth layer yet. It is only safe to use on a trusted local network or behind a reverse proxy that enforces access control.
- **No scan scheduling.** Tasks must be triggered explicitly via `start_scan`. There is no recurring or time-based scheduling.
- **Hardcoded default UUIDs.** The default scan config and scanner UUIDs are hardcoded constants matching a standard Greenbone Community Edition install. Non-standard deployments must pass explicit UUIDs.
- **Single GVM instance.** The server connects to one GVM instance, configured at startup. Multi-instance routing is not supported.
- **`get_scan_status` polls on a fixed interval.** The tool polls every 10 seconds. There is no push notification or webhook mechanism from GVM.
