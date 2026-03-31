"""OpenVAS MCP server — tool definitions."""

from __future__ import annotations

import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any

from gvm.errors import GvmError, GvmResponseError, GvmServerError
from mcp.server.fastmcp import Context, FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .auth import get_current_client
from .config import cfg
from .gvm_client import gmp_session
from .policy import get_policy

logger = logging.getLogger(__name__)

mcp = FastMCP("openvas", host=cfg.mcp_host, port=cfg.mcp_port)


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> Response:  # pragma: no cover
    return JSONResponse({"status": "ok"})


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _elem_text(elem: ET.Element | None, tag: str, default: str = "") -> str:
    if elem is None:
        return default
    child = elem.find(tag)
    return (child.text or default) if child is not None else default


def _task_to_dict(task: ET.Element) -> dict[str, Any]:
    last_report_elem = task.find("last_report/report")
    return {
        "id": task.get("id", ""),
        "name": _elem_text(task, "name"),
        "status": _elem_text(task, "status"),
        "progress": _elem_text(task, "progress"),
        "last_report": last_report_elem.get("id", "") if last_report_elem is not None else "",
    }


def _target_to_dict(target: ET.Element) -> dict[str, Any]:
    return {
        "id": target.get("id", ""),
        "name": _elem_text(target, "name"),
        "hosts": _elem_text(target, "hosts"),
        "port_list": target.findtext("port_list/name", ""),
    }


def _err(code: str, message: str) -> dict[str, Any]:
    """Return a structured error dict."""
    return {"error": True, "code": code, "message": message}


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
    return None


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_targets() -> list[dict[str, Any]] | dict[str, Any]:
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
    try:
        with gmp_session() as gmp:
            response = gmp.get_targets()
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
        return _err("connection_error", f"Could not connect to GVM: {e}")
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
def create_target(name: str, hosts: str, port_list_id: str = "") -> dict[str, Any]:
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
    logger.info(
        "tool invoked",
        extra={
            "tool": "create_target",
            "params": {"name": name, "hosts": hosts},
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    if err := _validate_name(name):
        return err
    if not hosts.strip():
        return _err("validation_error", "hosts must not be empty")
    if port_list_id and (err := _validate_uuid(port_list_id, "port_list_id")):
        return err

    host_list = [h.strip() for h in hosts.split(",") if h.strip()]
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
    try:
        with gmp_session() as gmp:
            response = gmp.create_target(**kwargs)
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
        return _err("connection_error", f"Could not connect to GVM: {e}")
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
def list_tasks() -> list[dict[str, Any]] | dict[str, Any]:
    """Return all scan tasks (active and historical)."""
    identity = get_current_client()
    if not get_policy().is_tool_allowed("list_tasks", identity):
        logger.warning(
            "operation denied",
            extra={"tool": "list_tasks", "client_id": identity.client_id if identity else "stdio"},
        )
        return _err("forbidden", "Operation not permitted")
    logger.info(
        "tool invoked",
        extra={"tool": "list_tasks", "client_id": identity.client_id if identity else "stdio"},
    )
    try:
        with gmp_session() as gmp:
            response = gmp.get_tasks()
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
        return _err("connection_error", f"Could not connect to GVM: {e}")
    result = [_task_to_dict(t) for t in response.findall("task")]
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
def start_scan(
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

    try:
        with gmp_session() as gmp:
            max_scans = get_policy().max_concurrent_scans(identity)
            if max_scans > 0:
                running_resp = gmp.get_tasks(filter_string="status=Running")
                active = len(running_resp.findall("task"))
                if active >= max_scans:
                    logger.warning(
                        "concurrent scan limit reached",
                        extra={
                            "tool": "start_scan",
                            "limit": max_scans,
                            "client_id": identity.client_id if identity else "stdio",
                        },
                    )
                    return _err("rate_limited", f"Maximum concurrent scans ({max_scans}) reached")

            task = gmp.create_task(
                name=name,
                config_id=scan_config_id or FULL_AND_FAST,
                target_id=target_id,
                scanner_id=scanner_id or DEFAULT_SCANNER,
            )
            task_id = task.get("id", "")
            gmp.start_task(task_id)
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
        return _err("connection_error", f"Could not connect to GVM: {e}")

    result = {"task_id": task_id, "status": "started"}
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
async def get_scan_status(task_id: str, ctx: Context) -> dict[str, Any]:
    """Monitor a scan task, pushing progress notifications until it reaches a terminal state.

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

    while True:

        def _fetch():
            with gmp_session() as gmp:
                return gmp.get_task(task_id)

        try:
            response = await asyncio.to_thread(_fetch)
        except (GvmError, OSError) as e:
            logger.error(
                "error polling scan status", extra={"tool": "get_scan_status", "error": str(e)}
            )
            return _err("gvm_error", str(e))

        task = response.find("task")
        if task is None:
            return _err("not_found", f"Task {task_id} not found")

        info = _task_to_dict(task)
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
def fetch_scan_results(
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

    try:
        with gmp_session() as gmp:
            task_resp = gmp.get_task(task_id)
            task = task_resp.find("task")
            if task is None:
                return _err("not_found", f"Task {task_id} not found")

            last_report = task.find("last_report/report")
            report_id = last_report.get("id", "") if last_report is not None else ""

            if not report_id:
                return _err("not_found", "No completed report found for this task")

            report_resp = gmp.get_report(
                report_id,
                filter_string=f"severity>{min_severity - 0.001:.3f}",
                ignore_pagination=True,
                details=True,
            )
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
        return _err("connection_error", f"Could not connect to GVM: {e}")

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
                "host": result.findtext("host") or "",
                "port": result.findtext("port") or "",
                "severity": severity,
                "threat": _elem_text(result, "threat"),
                "description": _elem_text(result, "description"),
                "cve": [ref.get("id", "") for ref in result.findall(".//ref[@type='cve']")],
            }
        )

    results.sort(key=lambda r: r["severity"], reverse=True)
    logger.info(
        "tool completed",
        extra={
            "tool": "fetch_scan_results",
            "status": "ok",
            "count": len(results),
            "client_id": identity.client_id if identity else "stdio",
        },
    )
    return results
