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

CIDR enforcement happens at `create_target` time, where hosts are explicitly defined. It does not re-check hosts at `start_scan` or `start_task` time (which receive only a target or task UUID) — this is a known limitation documented below.

## Minimal runtime dependencies

`python-gvm` for GMP, `mcp[cli]` for the MCP server, `pyyaml` for policy files. No framework beyond what the protocol requires.

---

# Known limitations

## Policy & authorization

- **CIDR policy enforced at target creation only.** The `start_scan` tool takes a `target_id`, not a host list, and `start_task` takes only a task UUID. CIDR policy is not re-validated at scan time — a target created before a more restrictive policy was deployed can still be scanned, and an existing task can still be re-run. Enforce policy at `create_target` time and manage target lifecycle accordingly.

- **Hostnames not matched by CIDR rules.** When a client has explicit CIDR restrictions, hostname targets (e.g. `myhost.example.com`) are denied — they cannot be resolved to an IP at policy check time. Use IP addresses or CIDR ranges in targets when CIDR policy is active.

- **No API key expiry.** API keys are static strings with no built-in rotation or TTL. Revoke a key by removing it from `MCP_API_KEYS` and restarting the server.

## Scanning

- **No scan scheduling.** Tasks must be triggered explicitly via `start_scan` (new task) or `start_task` (re-run an existing one). There is no recurring or time-based scheduling; GVM's own schedules are untouched by either tool.

- **`start_task`'s status check is advisory.** The tool reads a task's status and returns `conflict` if it is already active, but the status can change between that read and the start — a GVM schedule, the GSA web UI, another MCP replica or a second worker process can all start the same task. `_scan_start_lock` serialises starts within one process only. GVM remains authoritative and its rejection surfaces as `gvm_response_error`.

- **The concurrency limit counts only `status=Running`.** Tasks in `Requested` or `Queued` are not counted, so a burst of starts can briefly overshoot `max_concurrent_scans`. `start_task` makes this cheaper to trigger than `start_scan` did.

- **`list_tasks` is paged by GVM.** With no `filter_string`, GVM applies the service account's default rows-per-page (100 on a stock install), so large deployments see a truncated list. Pass `rows=-1` for every task, or `rows=N` to page. Note that `rows=-1` is not literally unlimited: gvmd rewrites it to its maximum page size (1000 on a stock install). A supplied filter replaces GVM's default filter wholesale rather than merging with it.

- **GMP filter terms are OR-ed unless joined with `and`.** `severity>5 total<4` returns the union of both terms — *more* rows than either alone — which reads as the filter having been ignored. This is GMP's own semantics; the server documents it in the `list_tasks` tool description but does not rewrite the caller's filter, since silently converting OR to AND would be exactly the kind of hidden behaviour the bridge avoids.

- **Filter keywords are allowlisted because GVM drops unknown ones silently.** gvmd discards a filter term whose keyword it does not recognise (`zzzbogus<4`) or whose value it cannot parse (`last<yesterday`) without reporting an error and without any marker in the response — the caller gets a wider result set and no way to detect it. Acting on that (starting a batch of tasks, say) would hit the wrong set, so `_validate_filter` rejects those terms up front. The allowlist in `server.py` was verified term by term against a live gvmd; `progress`, `permission`, `alterable`, `in_use`, `observers`, `config`, `scanner`, `average_duration`, `overrides`, `notes`, `levels` and `timezone` are deliberately absent because gvmd ignores them for tasks. A gvmd whose columns differ can fall back to `MCP_FILTER_VALIDATION=warn`, which restores the silent behaviour.

- **Relative filter dates use `m` for minutes and `M` for months.** `last<-1m` selects tasks whose last report is older than one *minute*, i.e. nearly all of them. The distinction is GMP's; the validator accepts both and the error message for an unparseable date spells the units out.

- **Task severity is the last report's severity.** GVM sends no task-level severity element, so `list_tasks` reports `last_report/report/severity`. A task that has never completed a report has `severity: null` — not `0.0`, which would be indistinguishable from a genuinely clean scan.

- **`host_count` comes from the target, not the task.** Task XML names a task's target but not its hosts, so `list_tasks` issues a second `get_targets` call in the same session and joins on target UUID, using gvmd's own computed `max_hosts` rather than re-implementing CIDR expansion. A target that was deleted, moved to the trashcan, or fell beyond gvmd's 1000-row page yields `host_count: null`. `get_scan_status` resolves its single target once and reuses the value for the rest of the poll.

- **`get_scan_status` polls on a fixed interval.** The tool polls every 10 seconds with no push notification or webhook mechanism from GVM. It stops and returns a `"timeout"` error once the configurable deadline (`GVM_SCAN_POLL_TIMEOUT`, default 3600 s) is reached; call the tool again to resume monitoring.

## Configuration & deployment

- **Hardcoded default UUIDs.** The default scan config and scanner UUIDs are hardcoded constants matching a standard [Greenbone Community Edition](https://greenbone.github.io/docs/latest/22.4/container/index.html#download) install. Non-standard deployments must pass explicit UUIDs.

- **Single GVM instance.** The server connects to one GVM instance, configured at startup. Multi-instance routing is not supported.

> [!NOTE]
> For CI-specific constraints and tradeoffs (GHCR mirror, auth secret), see [ci.md](ci.md).
