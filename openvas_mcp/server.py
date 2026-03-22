"""OpenVAS MCP server — tool definitions."""

from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

from .gvm_client import gmp_session

mcp = FastMCP("openvas")


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


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def list_targets() -> list[dict[str, Any]]:
    """Return all scan targets defined in OpenVAS."""
    with gmp_session() as gmp:
        response = gmp.get_targets()
    return [_target_to_dict(t) for t in response.findall("target")]


@mcp.tool()
def create_target(name: str, hosts: str, port_list_id: str = "") -> dict[str, Any]:
    """Create a scan target.

    Args:
        name: Human-readable name for the target.
        hosts: Comma-separated hostnames/IPs or CIDR ranges (e.g. "192.168.1.0/24").
        port_list_id: UUID of the port list to use. Defaults to "All TCP and Nmap top 100 UDP".
    """
    # Default: All TCP and Nmap top 100 UDP
    ALL_TCP_NMAP_TOP100_UDP = "730ef368-57e2-11e1-a90f-406186ea4fc5"
    kwargs: dict[str, Any] = {
        "name": name,
        "hosts": [h.strip() for h in hosts.split(",")],
        "port_list_id": port_list_id or ALL_TCP_NMAP_TOP100_UDP,
    }
    with gmp_session() as gmp:
        response = gmp.create_target(**kwargs)
    return {
        "id": response.get("id", ""),
        "status": response.get("status", ""),
        "status_text": response.get("status_text", ""),
    }


@mcp.tool()
def list_tasks() -> list[dict[str, Any]]:
    """Return all scan tasks (active and historical)."""
    with gmp_session() as gmp:
        response = gmp.get_tasks()
    return [_task_to_dict(t) for t in response.findall("task")]


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
    FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
    DEFAULT_SCANNER = "08b69003-5fc2-4037-a479-93b440211c73"

    with gmp_session() as gmp:
        task = gmp.create_task(
            name=name,
            config_id=scan_config_id or FULL_AND_FAST,
            target_id=target_id,
            scanner_id=scanner_id or DEFAULT_SCANNER,
        )
        task_id = task.get("id", "")
        gmp.start_task(task_id)

    return {"task_id": task_id, "status": "started"}


@mcp.tool()
async def get_scan_status(task_id: str, ctx: Context) -> dict[str, Any]:
    """Monitor a scan task, pushing progress notifications until it reaches a terminal state.

    Args:
        task_id: UUID of the scan task.
    """
    TERMINAL_STATES = {"Done", "Stopped", "Error"}
    POLL_INTERVAL = 10  # seconds

    while True:
        def _fetch():
            with gmp_session() as gmp:
                return gmp.get_task(task_id)

        response = await asyncio.to_thread(_fetch)
        task = response.find("task")
        if task is None:
            return {"error": f"Task {task_id} not found"}

        info = _task_to_dict(task)
        status = info["status"]

        try:
            progress = int(info["progress"])
        except (ValueError, TypeError):
            progress = 0

        await ctx.report_progress(progress, 100)
        await ctx.info(f"status={status} progress={progress}%")

        if status in TERMINAL_STATES:
            return info

        await asyncio.sleep(POLL_INTERVAL)


@mcp.tool()
def fetch_scan_results(task_id: str, min_severity: float = 0.0) -> list[dict[str, Any]]:
    """Retrieve vulnerability findings from the most recent report of a scan task.

    Args:
        task_id: UUID of the scan task.
        min_severity: Minimum CVSS severity score to include (0.0–10.0). Default 0.0 returns all.
    """
    with gmp_session() as gmp:
        task_resp = gmp.get_task(task_id)
        task = task_resp.find("task")
        if task is None:
            return [{"error": f"Task {task_id} not found"}]

        last_report = task.find("last_report/report")
        report_id = last_report.get("id", "") if last_report is not None else ""

        if not report_id:
            return [{"error": "No completed report found for this task"}]

        report_resp = gmp.get_report(
            report_id,
            filter_string=f"severity>{min_severity - 0.001:.3f}",
            ignore_pagination=True,
            details=True,
        )

    results = []
    for result in report_resp.findall(".//result"):
        severity_text = result.findtext("severity") or "0.0"
        try:
            severity = float(severity_text)
        except ValueError:
            severity = 0.0

        if severity < min_severity:
            continue

        results.append({
            "id": result.get("id", ""),
            "name": _elem_text(result, "name"),
            "host": result.findtext("host") or "",
            "port": result.findtext("port") or "",
            "severity": severity,
            "threat": _elem_text(result, "threat"),
            "description": _elem_text(result, "description"),
            "cve": [ref.get("id", "") for ref in result.findall(".//ref[@type='cve']")],
        })

    results.sort(key=lambda r: r["severity"], reverse=True)
    return results
