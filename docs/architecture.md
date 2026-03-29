# Architecture

<!-- Architecture diagram: see architecture.mmd (Mermaid source) -->
<img src="architecture.png" alt="Architecture diagram" width="600"/>

## Overview

```
AI agent → MCP client → OpenVAS MCP server → GMP API → OpenVAS / Greenbone
```

The MCP server is a stateless protocol bridge. It receives tool calls from an AI agent, translates them into GMP (Greenbone Management Protocol) operations, and returns structured JSON results. It holds no state between calls beyond the GVM connection parameters.

## Module structure

```
openvas_mcp/
  __main__.py       # entry point — validates config, initialises logging, starts server
  config.py         # all configuration loaded from environment variables
  logging_config.py # structured JSON logging to stderr
  server.py         # MCP tool definitions (@mcp.tool decorators)
  gvm_client.py     # GVM connection factory + gmp_session() context manager
```

## Request flow

1. AI agent calls an MCP tool (e.g. `start_scan`)
2. `server.py` validates inputs at the tool boundary (UUID format, string length, value ranges)
3. `gmp_session()` opens a connection to GVM and authenticates with the service account
4. The GMP method is called; the response is an XML `ElementTree`
5. The tool parses the XML into a plain Python dict and returns it
6. `gmp_session()` closes the connection on exit

On any error (connection failure, GMP error, validation failure), the tool returns a structured error dict — `{"error": true, "code": "...", "message": "..."}` — rather than raising an exception into the MCP framework.

## Connection modes

| Mode | When | Config |
|---|---|---|
| Unix socket | Default | `GVM_SOCKET_PATH` (default `/run/gvmd/gvmd.sock`) |
| Plain TCP | `GVM_HOST` set, `GVM_TLS` not set | `GVM_HOST`, `GVM_PORT` |
| TLS | `GVM_HOST` + `GVM_TLS=1` | `GVM_HOST`, `GVM_PORT` |

## Authentication model

The MCP server authenticates to GVM once per tool call using a single dedicated service account (`GVM_USERNAME` / `GVM_PASSWORD`). AI agents and end users never hold GVM credentials — they authenticate to the MCP server itself (on HTTP/SSE transport; stdio is inherently local).

## Logging

All output goes to stderr. The stdio transport uses stdout as the JSON-RPC channel; any byte written there corrupts the stream. Logs are emitted as structured JSON, one object per line, configurable via `LOG_LEVEL`.

```json
{"ts": "2026-03-29T10:00:00Z", "level": "INFO", "logger": "openvas_mcp.server", "msg": "tool invoked", "tool": "start_scan", "params": {"name": "...", "target_id": "..."}}
```
