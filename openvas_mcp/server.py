"""OpenVAS MCP server — tool definitions."""

from __future__ import annotations

import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any

from gvm.errors import GvmError, GvmResponseError, GvmServerError
from mcp.server.mcpserver import Context, MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .auth import ClientIdentity, get_current_client
from .config import cfg
from .gvm_client import gmp_session
from .policy import get_policy

logger = logging.getLogger(__name__)

# MCPServer takes no host/port: the bind address belongs to the transport, and
# is passed to sse_app()/streamable_http_app() and uvicorn in __main__.py.
mcp = MCPServer("openvas")

KNOWN_TOOLS: frozenset[str] = frozenset(
    {
        "create_target",
        "start_scan",
        "start_task",
        "get_scan_status",
        "fetch_scan_results",
        "list_targets",
        "list_tasks",
    }
)

# Serialises the check-and-start sequence in start_scan and start_task to
# prevent a TOCTOU race where concurrent callers all observe active < max_scans
# and all proceed. Process-local: it does not serialise across replicas, nor
# against scans started outside MCP.
_scan_start_lock = asyncio.Lock()


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> Response:  # pragma: no cover
    return JSONResponse({"status": "ok"})


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_MAX_FILTER_LEN = 1000

# GMP filter keywords, grouped by the value grammar gvmd expects. Every entry was
# verified against a live gvmd: a keyword outside this set is dropped from the filter
# without any error, which *widens* the result set, so unknown keywords are rejected at
# the boundary rather than passed through. Notably rejected because gvmd ignores them
# for tasks: progress, permission, alterable, in_use, observers, config, scanner,
# average_duration, overrides, notes, levels, timezone.
_FILTER_TEXT_COLUMNS = frozenset(
    {
        "uuid",
        "name",
        "comment",
        "status",
        "trend",
        "schedule",
        "owner",
        "hosts",
        "usage_type",
        "tag",
        "target",
        "threat",
    }
)
_FILTER_NUMERIC_COLUMNS = frozenset(
    {
        "total",
        "severity",
        "false_positive",
        "log",
        "low",
        "medium",
        "high",
        "result_hosts",
        "fp_per_host",
    }
)
_FILTER_DATE_COLUMNS = frozenset({"last", "created", "modified", "next_due"})
_FILTER_COLUMNS = _FILTER_TEXT_COLUMNS | _FILTER_NUMERIC_COLUMNS | _FILTER_DATE_COLUMNS

# Paging/sorting keywords: not columns, but honoured by gvmd.
_FILTER_NUMERIC_CONTROLS = frozenset({"rows", "first", "min_qod"})
_FILTER_SORT_CONTROLS = frozenset({"sort", "sort-reverse"})
_FILTER_KEYWORDS = (
    _FILTER_COLUMNS | _FILTER_NUMERIC_CONTROLS | _FILTER_SORT_CONTROLS | {"apply_overrides"}
)

# Boolean operators. GMP ORs adjacent terms by default, so "and" is significant.
_FILTER_BOOLEANS = frozenset({"and", "or", "not"})

_FILTER_TERM_RE = re.compile(r"^(?P<keyword>[A-Za-z_][A-Za-z0-9_-]*)(?P<op>!?[=~<>])(?P<value>.*)$")
_FILTER_NUMBER_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)$")
# Absolute (2026-08-01, 2026-08-01T14:30[:00]) or relative (-30d) — see _RELATIVE_UNITS_HELP.
_FILTER_DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?)?|[+-]?\d+[smhdwMy])$")

_RELATIVE_UNITS_HELP = (
    "relative units are s=seconds, m=minutes, h=hours, d=days, w=weeks, M=months, "
    "y=years — note that m is minutes and M is months"
)

# Task states GVM refuses to start from. A denylist rather than an allowlist of
# startable states, so a status a future gvmd adds falls through to GVM, which
# is authoritative either way.
_ACTIVE_TASK_STATES = frozenset({"Requested", "Queued", "Running", "Stop Requested", "Processing"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _elem_text(elem: ET.Element | None, tag: str, default: str = "") -> str:
    if elem is None:
        return default
    child = elem.find(tag)
    return (child.text or default) if child is not None else default


def _elem_attr(elem: ET.Element | None, tag: str, attr: str, default: str = "") -> str:
    if elem is None:
        return default
    child = elem.find(tag)
    return child.get(attr, default) if child is not None else default


def _elem_int(elem: ET.Element | None, tag: str) -> int | None:
    """Return a child element's text as an int, or None if absent or unparseable."""
    try:
        return int(_elem_text(elem, tag).strip())
    except (TypeError, ValueError):
        return None


def _elem_float(elem: ET.Element | None, tag: str) -> float | None:
    """Return a child element's text as a float, or None if absent or unparseable."""
    try:
        return float(_elem_text(elem, tag).strip())
    except (TypeError, ValueError):
        return None


def _task_to_dict(task: ET.Element, host_count: int | None = None) -> dict[str, Any]:
    """Flatten a GMP <task> element.

    severity and last_report_date come from the task's last report — gvmd sends no
    task-level severity. host_count is supplied by the caller from the task's target
    (see _target_host_counts); None anywhere means "unresolved", never zero.
    """
    last_report_elem = task.find("last_report/report")
    target_elem = task.find("target")
    return {
        "id": task.get("id", ""),
        "name": _elem_text(task, "name"),
        "status": _elem_text(task, "status"),
        "progress": _elem_text(task, "progress"),
        "last_report": last_report_elem.get("id", "") if last_report_elem is not None else "",
        "last_report_date": _elem_text(last_report_elem, "timestamp"),
        "severity": _elem_float(last_report_elem, "severity"),
        "report_count": _elem_int(task, "report_count"),
        "finished_report_count": _elem_int(task, "report_count/finished"),
        "trend": _elem_text(task, "trend"),
        "target_id": target_elem.get("id", "") if target_elem is not None else "",
        "target_name": _elem_text(target_elem, "name"),
        "host_count": host_count,
    }


def _target_to_dict(target: ET.Element) -> dict[str, Any]:
    return {
        "id": target.get("id", ""),
        "name": _elem_text(target, "name"),
        "hosts": _elem_text(target, "hosts"),
        "exclude_hosts": _elem_text(target, "exclude_hosts"),
        # gvmd computes max_hosts itself (CIDR ranges expanded); the bridge does not
        # re-implement that arithmetic.
        "host_count": _elem_int(target, "max_hosts"),
        "port_list": target.findtext("port_list/name", ""),
    }


def _target_host_counts(response: ET.Element) -> dict[str, int | None]:
    """Map target UUID to its host count, for joining onto tasks."""
    return {t.get("id", ""): _elem_int(t, "max_hosts") for t in response.findall("target")}


def _err(code: str, message: str) -> dict[str, Any]:
    """Return a structured error dict."""
    return {"error": True, "code": code, "message": message}


def _sanitize_os_error(e: OSError) -> str:
    """Return a generic connection error message, omitting socket paths and fs details."""
    return f"Could not connect to GVM: [{e.errno}] {e.strerror}"


def _validate_uuid(value: str, field_name: str) -> dict[str, Any] | None:
    """Return an error dict if value is not a valid UUID, else None."""
    if not _UUID_RE.match(value):
        return _err("validation_error", f"{field_name} must be a valid UUID, got: {value!r}")
    return None


def _validate_name(value: str, field_name: str = "name") -> dict[str, Any] | None:
    if not value.strip():
        return _err("validation_error", f"{field_name} must not be empty")
    if len(value) > 255:
        return _err("validation_error", f"{field_name} must be 255 characters or fewer")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return _err("validation_error", f"{field_name} must not contain control characters")
    return None


def _split_filter_terms(value: str) -> list[str] | None:
    """Split a filter into whitespace-separated terms, honouring double quotes.

    Returns None if a double quote is left open.
    """
    terms: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in value:
        if char == '"':
            in_quotes = not in_quotes
        elif char.isspace() and not in_quotes:
            if current:
                terms.append("".join(current))
                current = []
        else:
            current.append(char)
    if in_quotes:
        return None
    if current:
        terms.append("".join(current))
    return terms


def _validate_filter_term(
    term: str, field_name: str, keywords: frozenset[str]
) -> dict[str, Any] | None:
    """Validate one filter term, or None if it is acceptable."""
    if term.lower() in _FILTER_BOOLEANS:
        return None
    match = _FILTER_TERM_RE.match(term)
    if match is None:
        # A bare word is a free-text search across the entity's text columns.
        return None

    keyword = match["keyword"]
    value = match["value"]
    if keyword not in keywords:
        return _err(
            "validation_error",
            f"{field_name}: unsupported keyword {keyword!r} in term {term!r} — GVM would "
            f"silently ignore it and return a wider result set. "
            f"Supported keywords: {', '.join(sorted(keywords))}",
        )
    if keyword in _FILTER_DATE_COLUMNS and not _FILTER_DATE_RE.match(value):
        return _err(
            "validation_error",
            f"{field_name}: {keyword!r} needs a date, got {value!r}. Use an absolute date "
            f"(2026-08-01, 2026-08-01T14:30) or a relative offset (-30d); "
            f"{_RELATIVE_UNITS_HELP}",
        )
    if (
        keyword in _FILTER_NUMERIC_COLUMNS or keyword in _FILTER_NUMERIC_CONTROLS
    ) and not _FILTER_NUMBER_RE.match(value):
        return _err("validation_error", f"{field_name}: {keyword!r} needs a number, got {value!r}")
    if keyword == "apply_overrides" and value not in ("0", "1"):
        return _err(
            "validation_error", f"{field_name}: 'apply_overrides' must be 0 or 1, got {value!r}"
        )
    if keyword in _FILTER_SORT_CONTROLS and value not in _FILTER_COLUMNS:
        return _err(
            "validation_error",
            f"{field_name}: cannot sort by {value!r}. "
            f"Sortable columns: {', '.join(sorted(_FILTER_COLUMNS))}",
        )
    return None


def _validate_filter(
    value: str,
    field_name: str = "filter_string",
    keywords: frozenset[str] = _FILTER_KEYWORDS,
) -> dict[str, Any] | None:
    """Validate a GMP filter term.

    The value is not escaped here: python-gvm sets it as an XML attribute, which
    ElementTree escapes on serialisation.

    Keywords and values are checked because gvmd discards a term it cannot parse
    without reporting an error — the caller would get a silently wider result set and
    no way to tell. Set MCP_FILTER_VALIDATION=warn to log rejections and pass the
    filter through unchanged instead (escape hatch for a gvmd whose filter columns
    differ from the ones this allowlist was verified against).
    """
    if len(value) > _MAX_FILTER_LEN:
        return _err(
            "validation_error", f"{field_name} must be {_MAX_FILTER_LEN} characters or fewer"
        )
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        return _err("validation_error", f"{field_name} must not contain control characters")

    terms = _split_filter_terms(value)
    if terms is None:
        return _err("validation_error", f"{field_name} has an unbalanced double quote")
    for term in terms:
        err = _validate_filter_term(term, field_name, keywords)
        if err is None:
            continue
        if cfg.mcp_filter_validation == "warn":
            logger.warning(
                "filter term rejected but passed through (MCP_FILTER_VALIDATION=warn)",
                extra={"term": term, "reason": err["message"]},
            )
            continue
        return err
    return None


def _concurrency_error(
    gmp: Any, identity: ClientIdentity | None, tool: str
) -> dict[str, Any] | None:
    """Return a rate_limited error if the GVM-global active-scan limit is reached.

    Called from inside the worker thread, under _scan_start_lock.
    """
    max_scans = get_policy().max_concurrent_scans(identity)
    if max_scans <= 0:
        return None
    running_resp = gmp.get_tasks(filter_string="status=Running")
    if len(running_resp.findall("task")) < max_scans:
        return None
    logger.warning("concurrent scan limit reached", extra={"tool": tool, "limit": max_scans})
    return _err(
        "rate_limited",
        f"Maximum concurrent scans ({max_scans}) reached "
        f"(this is a GVM-global count, not limited to this MCP session)",
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_targets() -> list[dict[str, Any]] | dict[str, Any]:
    """Return all scan targets defined in OpenVAS."""
    identity = get_current_client()
    if not get_policy().is_tool_allowed("list_targets", identity):
        logger.warning(
            "operation denied",
            extra={
                "tool": "list_targets",
                "client_id": identity.client_id if identity else "stdio",
            },
        )
        return _err("forbidden", "Operation not permitted")
    logger.info(
        "tool invoked",
        extra={"tool": "list_targets", "client_id": identity.client_id if identity else "stdio"},
    )

    def _call():
        with gmp_session() as gmp:
            return gmp.get_targets()

    try:
        response = await asyncio.to_thread(_call)
    except GvmResponseError as e:
        logger.error("GMP response error", extra={"tool": "list_targets", "error": str(e)})
        return _err("gvm_response_error", str(e))
    except GvmServerError as e:
        logger.error("GMP server error", extra={"tool": "list_targets", "error": str(e)})
        return _err("gvm_server_error", str(e))
    except GvmError as e:
        logger.error("GMP error", extra={"tool": "list_targets", "error": str(e)})
        return _err("gvm_error", str(e))
    except OSError as e:
        logger.error("connection error", extra={"tool": "list_targets", "error": str(e)})
        return _err("connection_error", _sanitize_os_error(e))
    result = [_target_to_dict(t) for t in response.findall("target")]
    logger.info(
        "tool completed",
        extra={
            "tool": "list_targets",
            "status": "ok",
            "count": len(result),
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    return result


@mcp.tool()
async def create_target(name: str, hosts: str, port_list_id: str = "") -> dict[str, Any]:
    """Create a scan target.

    Args:
        name: Human-readable name for the target.
        hosts: Comma-separated hostnames/IPs or CIDR ranges (e.g. "192.168.1.0/24").
        port_list_id: UUID of the port list to use. Defaults to "All TCP and Nmap top 100 UDP".
    """
    identity = get_current_client()
    if not get_policy().is_tool_allowed("create_target", identity):
        logger.warning(
            "operation denied",
            extra={
                "tool": "create_target",
                "client_id": identity.client_id if identity else "stdio",
            },
        )
        return _err("forbidden", "Operation not permitted")
    if err := _validate_name(name):
        return err
    if not hosts.strip():
        return _err("validation_error", "hosts must not be empty")
    if port_list_id and (err := _validate_uuid(port_list_id, "port_list_id")):
        return err

    host_list = [h.strip() for h in hosts.split(",") if h.strip()]
    logger.info(
        "tool invoked",
        extra={
            "tool": "create_target",
            "params": {"name": name, "host_count": len(host_list)},
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    policy = get_policy()
    denied_hosts = [h for h in host_list if not policy.is_host_allowed(h, identity)]
    if denied_hosts:
        logger.warning(
            "host denied by policy",
            extra={
                "tool": "create_target",
                "denied": denied_hosts,
                "client_id": identity.client_id if identity else "stdio",
            },
        )
        return _err("forbidden", f"Target hosts not permitted by policy: {', '.join(denied_hosts)}")

    ALL_TCP_NMAP_TOP100_UDP = "730ef368-57e2-11e1-a90f-406186ea4fc5"
    kwargs: dict[str, Any] = {
        "name": name,
        "hosts": host_list,
        "port_list_id": port_list_id or ALL_TCP_NMAP_TOP100_UDP,
    }

    def _call():
        with gmp_session() as gmp:
            return gmp.create_target(**kwargs)

    try:
        response = await asyncio.to_thread(_call)
    except GvmResponseError as e:
        logger.error("GMP response error", extra={"tool": "create_target", "error": str(e)})
        return _err("gvm_response_error", str(e))
    except GvmServerError as e:
        logger.error("GMP server error", extra={"tool": "create_target", "error": str(e)})
        return _err("gvm_server_error", str(e))
    except GvmError as e:
        logger.error("GMP error", extra={"tool": "create_target", "error": str(e)})
        return _err("gvm_error", str(e))
    except OSError as e:
        logger.error("connection error", extra={"tool": "create_target", "error": str(e)})
        return _err("connection_error", _sanitize_os_error(e))
    result = {
        "id": response.get("id", ""),
        "status": response.get("status", ""),
        "status_text": response.get("status_text", ""),
    }
    logger.info(
        "tool completed",
        extra={
            "tool": "create_target",
            "status": "ok",
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    return result


@mcp.tool()
async def list_tasks(filter_string: str = "") -> list[dict[str, Any]] | dict[str, Any]:
    """Return scan tasks (active and historical), with severity, last-report and target info.

    Each row carries: id, name, status, progress, last_report (report UUID),
    last_report_date (ISO 8601), severity (of the last report), report_count,
    finished_report_count, trend, target_id, target_name and host_count. A null
    severity or host_count means "could not be resolved", not zero.

    Args:
        filter_string: Optional GMP filter term, e.g. "name~weekly", "status=Done",
            "tag=reports rows=20". Empty returns GVM's default task list. Three things
            about GMP filter syntax are easy to get wrong:

            - Terms are combined with OR unless you write "and" between them, so
              "severity>5 total<4" returns the union (more rows, not fewer). Write
              "severity>5 and total<4" to intersect.
            - Relative dates use s=seconds, m=minutes, h=hours, d=days, w=weeks,
              M=months, y=years. "last<-1m" means "older than one minute" and matches
              almost everything; "last<-1M" means "older than one month".
            - GVM applies a default page size and caps it at 1000; pass "rows=-1" for
              as many as GVM will return.

            Example — tasks with a high-severity last report from over a month ago:
            "severity>5 and last<-1M rows=-1".

            An unsupported keyword or an unparseable value is rejected with
            validation_error rather than passed on, because GVM would drop the term
            silently and return a wider set than asked for.
    """
    identity = get_current_client()
    if not get_policy().is_tool_allowed("list_tasks", identity):
        logger.warning(
            "operation denied",
            extra={"tool": "list_tasks", "client_id": identity.client_id if identity else "stdio"},
        )
        return _err("forbidden", "Operation not permitted")
    filter_string = filter_string.strip()
    logger.info(
        "tool invoked",
        extra={
            "tool": "list_tasks",
            "params": {"filter_string": filter_string},
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    if filter_string and (err := _validate_filter(filter_string)):
        return err

    def _call():
        with gmp_session() as gmp:
            # Task XML carries the target's id and name but not its hosts, so the
            # target list is fetched in the same session to resolve host_count.
            return gmp.get_tasks(filter_string=filter_string), gmp.get_targets(
                filter_string="rows=-1"
            )

    try:
        response, targets_response = await asyncio.to_thread(_call)
    except GvmResponseError as e:
        logger.error("GMP response error", extra={"tool": "list_tasks", "error": str(e)})
        return _err("gvm_response_error", str(e))
    except GvmServerError as e:
        logger.error("GMP server error", extra={"tool": "list_tasks", "error": str(e)})
        return _err("gvm_server_error", str(e))
    except GvmError as e:
        logger.error("GMP error", extra={"tool": "list_tasks", "error": str(e)})
        return _err("gvm_error", str(e))
    except OSError as e:
        logger.error("connection error", extra={"tool": "list_tasks", "error": str(e)})
        return _err("connection_error", _sanitize_os_error(e))
    host_counts = _target_host_counts(targets_response)
    result = [
        _task_to_dict(task, host_counts.get(_elem_attr(task, "target", "id")))
        for task in response.findall("task")
    ]
    logger.info(
        "tool completed",
        extra={
            "tool": "list_tasks",
            "status": "ok",
            "count": len(result),
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    return result


@mcp.tool()
async def start_scan(
    name: str,
    target_id: str,
    scanner_id: str = "",
    scan_config_id: str = "",
) -> dict[str, Any]:
    """Create and immediately start a vulnerability scan.

    Args:
        name: Name for the new scan task.
        target_id: UUID of the target to scan.
        scanner_id: UUID of the scanner to use. Defaults to OpenVAS default scanner.
        scan_config_id: UUID of the scan config. Defaults to "Full and fast".
    """
    identity = get_current_client()
    if not get_policy().is_tool_allowed("start_scan", identity):
        logger.warning(
            "operation denied",
            extra={"tool": "start_scan", "client_id": identity.client_id if identity else "stdio"},
        )
        return _err("forbidden", "Operation not permitted")
    logger.info(
        "tool invoked",
        extra={
            "tool": "start_scan",
            "params": {"name": name, "target_id": target_id},
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    if err := _validate_name(name):
        return err
    if err := _validate_uuid(target_id, "target_id"):
        return err
    if scanner_id and (err := _validate_uuid(scanner_id, "scanner_id")):
        return err
    if scan_config_id and (err := _validate_uuid(scan_config_id, "scan_config_id")):
        return err

    FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
    DEFAULT_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"

    def _check_and_start() -> tuple[str | None, str, dict[str, Any] | None]:
        with gmp_session() as gmp:
            if limit_err := _concurrency_error(gmp, identity, "start_scan"):
                return None, "", limit_err
            task = gmp.create_task(
                name=name,
                config_id=scan_config_id or FULL_AND_FAST,
                target_id=target_id,
                scanner_id=scanner_id or DEFAULT_SCANNER,
            )
            tid = task.get("id", "")
            if not tid:
                return None, "", _err("gvm_error", "GVM returned no task ID after create_task")
            return tid, gmp.start_task(tid).findtext("report_id", ""), None

    try:
        async with _scan_start_lock:
            task_id, report_id, err = await asyncio.to_thread(_check_and_start)
    except GvmResponseError as e:
        logger.error("GMP response error", extra={"tool": "start_scan", "error": str(e)})
        return _err("gvm_response_error", str(e))
    except GvmServerError as e:
        logger.error("GMP server error", extra={"tool": "start_scan", "error": str(e)})
        return _err("gvm_server_error", str(e))
    except GvmError as e:
        logger.error("GMP error", extra={"tool": "start_scan", "error": str(e)})
        return _err("gvm_error", str(e))
    except OSError as e:
        logger.error("connection error", extra={"tool": "start_scan", "error": str(e)})
        return _err("connection_error", _sanitize_os_error(e))

    if err:
        return err

    result = {"task_id": task_id, "report_id": report_id, "status": "started"}
    logger.info(
        "tool completed",
        extra={
            "tool": "start_scan",
            "status": "ok",
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    return result


@mcp.tool()
async def start_task(task_id: str) -> dict[str, Any]:
    """Start (re-run) an existing scan task, adding a new report to its history.

    Unlike start_scan, this creates no new task. Use list_tasks (optionally with a
    filter_string) to find the task UUID.

    Args:
        task_id: UUID of the existing scan task to start.
    """
    identity = get_current_client()
    if not get_policy().is_tool_allowed("start_task", identity):
        logger.warning(
            "operation denied",
            extra={"tool": "start_task", "client_id": identity.client_id if identity else "stdio"},
        )
        return _err("forbidden", "Operation not permitted")
    logger.info(
        "tool invoked",
        extra={
            "tool": "start_task",
            "params": {"task_id": task_id},
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    if err := _validate_uuid(task_id, "task_id"):
        return err

    def _check_and_start() -> tuple[str | None, dict[str, Any] | None]:
        with gmp_session() as gmp:
            # Existence and status are checked before the concurrency limit, so that
            # re-running the task that is itself running reports conflict (not
            # retriable) rather than rate_limited (retriable).
            task = gmp.get_task(task_id).find("task")
            if task is None:
                return None, _err("not_found", f"Task {task_id} not found")
            # Advisory only: GVM is authoritative and may still reject the start if
            # the status changes between this read and start_task.
            status = _elem_text(task, "status")
            if status in _ACTIVE_TASK_STATES:
                return None, _err(
                    "conflict", f"Task {task_id} is already active (status: {status})"
                )
            if limit_err := _concurrency_error(gmp, identity, "start_task"):
                return None, limit_err
            return gmp.start_task(task_id).findtext("report_id", ""), None

    try:
        async with _scan_start_lock:
            report_id, err = await asyncio.to_thread(_check_and_start)
    except GvmResponseError as e:
        logger.error("GMP response error", extra={"tool": "start_task", "error": str(e)})
        return _err("gvm_response_error", str(e))
    except GvmServerError as e:
        logger.error("GMP server error", extra={"tool": "start_task", "error": str(e)})
        return _err("gvm_server_error", str(e))
    except GvmError as e:
        logger.error("GMP error", extra={"tool": "start_task", "error": str(e)})
        return _err("gvm_error", str(e))
    except OSError as e:
        logger.error("connection error", extra={"tool": "start_task", "error": str(e)})
        return _err("connection_error", _sanitize_os_error(e))

    if err:
        return err

    result = {"task_id": task_id, "report_id": report_id, "status": "started"}
    logger.info(
        "tool completed",
        extra={
            "tool": "start_task",
            "status": "ok",
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    return result


@mcp.tool()
async def get_scan_status(task_id: str, ctx: Context) -> dict[str, Any]:
    """Monitor a scan task, pushing progress notifications until it reaches a terminal state.

    Returns the same row shape as list_tasks, including severity, last_report_date and
    host_count.

    Args:
        task_id: UUID of the scan task.
    """
    identity = get_current_client()
    if not get_policy().is_tool_allowed("get_scan_status", identity):
        logger.warning(
            "operation denied",
            extra={
                "tool": "get_scan_status",
                "client_id": identity.client_id if identity else "stdio",
            },
        )
        return _err("forbidden", "Operation not permitted")
    logger.info(
        "tool invoked",
        extra={
            "tool": "get_scan_status",
            "params": {"task_id": task_id},
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    if err := _validate_uuid(task_id, "task_id"):
        return err

    TERMINAL_STATES = {"Done", "Stopped", "Error"}
    POLL_INTERVAL = 10  # seconds

    deadline = asyncio.get_running_loop().time() + cfg.scan_poll_timeout

    # Resolved from the task's target on the first poll only, then reused, so a long
    # poll does not refetch an unchanging value every interval.
    host_count: int | None = None
    host_count_resolved = False

    while True:
        if asyncio.get_running_loop().time() >= deadline:
            logger.warning(
                "scan poll timeout reached",
                extra={
                    "tool": "get_scan_status",
                    "timeout": cfg.scan_poll_timeout,
                    "task_id": task_id,
                    "client_id": identity.client_id if identity else "stdio",
                },
            )
            return _err(
                "timeout",
                f"Scan did not complete within {cfg.scan_poll_timeout}s; "
                "use get_scan_status again to continue monitoring",
            )

        # host_count_resolved is bound as a default so each iteration captures its
        # value at definition time rather than when the thread eventually runs.
        def _fetch(resolve_host_count: bool = not host_count_resolved):
            with gmp_session() as gmp:
                response = gmp.get_task(task_id)
                if not resolve_host_count:
                    return response, None
                target_uuid = _elem_attr(response.find("task"), "target", "id")
                if not target_uuid:
                    return response, None
                try:
                    target = gmp.get_target(target_uuid).find("target")
                except GvmError as target_err:
                    # host_count is secondary here; monitoring must not stop because the
                    # target is unreadable. list_tasks, where host_count is a headline
                    # field, still fails loudly.
                    logger.warning(
                        "could not resolve target for host_count",
                        extra={"tool": "get_scan_status", "error": str(target_err)},
                    )
                    return response, None
                return response, _elem_int(target, "max_hosts")

        try:
            response, resolved_host_count = await asyncio.to_thread(_fetch)
        except OSError as e:
            logger.error(
                "error polling scan status", extra={"tool": "get_scan_status", "error": str(e)}
            )
            return _err("connection_error", _sanitize_os_error(e))
        except GvmError as e:
            logger.error(
                "error polling scan status", extra={"tool": "get_scan_status", "error": str(e)}
            )
            return _err("gvm_error", str(e))

        task = response.find("task")
        if task is None:
            return _err("not_found", f"Task {task_id} not found")

        if not host_count_resolved:
            host_count = resolved_host_count
            host_count_resolved = True

        info = _task_to_dict(task, host_count)
        status = info["status"]

        try:
            progress = int(info["progress"])
        except (ValueError, TypeError):
            progress = 0

        await ctx.report_progress(progress, 100)
        await ctx.info(f"status={status} progress={progress}%")

        if status in TERMINAL_STATES:
            logger.info(
                "tool completed",
                extra={
                    "tool": "get_scan_status",
                    "status": status,
                    "client_id": identity.client_id if identity else "stdio",
                },
            )
            return info

        await asyncio.sleep(POLL_INTERVAL)


@mcp.tool()
async def fetch_scan_results(
    task_id: str, min_severity: float = 0.0
) -> list[dict[str, Any]] | dict[str, Any]:
    """Retrieve vulnerability findings from the most recent report of a scan task.

    Args:
        task_id: UUID of the scan task.
        min_severity: Minimum CVSS severity score to include (0.0–10.0). Default 0.0 returns all.
    """
    identity = get_current_client()
    if not get_policy().is_tool_allowed("fetch_scan_results", identity):
        logger.warning(
            "operation denied",
            extra={
                "tool": "fetch_scan_results",
                "client_id": identity.client_id if identity else "stdio",
            },
        )
        return _err("forbidden", "Operation not permitted")
    logger.info(
        "tool invoked",
        extra={
            "tool": "fetch_scan_results",
            "params": {"task_id": task_id, "min_severity": min_severity},
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    if err := _validate_uuid(task_id, "task_id"):
        return err
    if not (0.0 <= min_severity <= 10.0):
        return _err(
            "validation_error", f"min_severity must be between 0.0 and 10.0, got {min_severity}"
        )

    def _call():
        with gmp_session() as gmp:
            task_resp = gmp.get_task(task_id)
            task_elem = task_resp.find("task")
            if task_elem is None:
                return None, None
            last_report = task_elem.find("last_report/report")
            report_id = last_report.get("id", "") if last_report is not None else ""
            if not report_id:
                return task_elem, None
            return task_elem, gmp.get_report(
                report_id,
                filter_string=f"severity>{min_severity - 0.001:.3f}",
                ignore_pagination=True,
                details=True,
            )

    try:
        task_elem, report_resp = await asyncio.to_thread(_call)
    except GvmResponseError as e:
        logger.error("GMP response error", extra={"tool": "fetch_scan_results", "error": str(e)})
        return _err("gvm_response_error", str(e))
    except GvmServerError as e:
        logger.error("GMP server error", extra={"tool": "fetch_scan_results", "error": str(e)})
        return _err("gvm_server_error", str(e))
    except GvmError as e:
        logger.error("GMP error", extra={"tool": "fetch_scan_results", "error": str(e)})
        return _err("gvm_error", str(e))
    except OSError as e:
        logger.error("connection error", extra={"tool": "fetch_scan_results", "error": str(e)})
        return _err("connection_error", _sanitize_os_error(e))

    if task_elem is None:
        return _err("not_found", f"Task {task_id} not found")
    if report_resp is None:
        return _err("not_found", "No completed report found for this task")

    results = []
    for result in report_resp.findall(".//result"):
        severity_text = result.findtext("severity") or "0.0"
        try:
            severity = float(severity_text)
        except ValueError:
            severity = 0.0

        if severity < min_severity:
            continue

        results.append(
            {
                "id": result.get("id", ""),
                "name": _elem_text(result, "name"),
                "host": result.findtext("host/ip") or result.findtext("host") or "",
                "port": result.findtext("port") or "",
                "severity": severity,
                "threat": _elem_text(result, "threat"),
                "description": _elem_text(result, "description"),
                "cve": [ref.get("id", "") for ref in result.findall(".//ref[@type='cve']")],
            }
        )

    results.sort(key=lambda r: r["severity"], reverse=True)

    cap = cfg.report_max_results  # 0 means unlimited; only applied when > 0
    truncated = cap > 0 and len(results) > cap
    if truncated:
        results = results[:cap]
        logger.warning(
            "report results truncated",
            extra={
                "tool": "fetch_scan_results",
                "cap": cap,
                "client_id": identity.client_id if identity else "stdio",
            },
        )

    logger.info(
        "tool completed",
        extra={
            "tool": "fetch_scan_results",
            "status": "ok",
            "count": len(results),
            "truncated": truncated,
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    if truncated:
        return {"results": results, "truncated": True, "cap": cap}
    return results
