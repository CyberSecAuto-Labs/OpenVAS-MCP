"""Integration tests — exercise MCP tools against a live GVM instance.

Run against the bundled Greenbone stack (docker/openvas/compose.yaml), which
exposes gvmd via the gvmd-socket-proxy service on port 9393 — the CI default:

    GVM_INTEGRATION=1 GVM_HOST=127.0.0.1 GVM_PORT=9393 GVM_PASSWORD=admin \
        pytest tests/integration/ -v

Or against a gvmd running on the same host, over its Unix socket:

    GVM_INTEGRATION=1 GVM_SOCKET_PATH=/run/gvmd/gvmd.sock \
        GVM_USERNAME=... GVM_PASSWORD=... pytest tests/integration/ -v
"""

from __future__ import annotations

import logging
import uuid

import pytest

from openvas_mcp.server import (
    create_target,
    fetch_scan_results,
    list_targets,
    list_tasks,
    start_task,
)

_PREFIX = "mcp-integration-"
_log = logging.getLogger(__name__)


def _name() -> str:
    return f"{_PREFIX}{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# list_targets
# ---------------------------------------------------------------------------


class TestListTargets:
    async def test_returns_list(self):
        result = await list_targets()
        assert isinstance(result, list)

    async def test_each_target_has_expected_keys(self):
        result = await list_targets()
        for target in result:
            assert "id" in target
            assert "name" in target
            assert "hosts" in target
            assert "exclude_hosts" in target
            assert "host_count" in target
            assert target["host_count"] is None or isinstance(target["host_count"], int)


# ---------------------------------------------------------------------------
# create_target
# ---------------------------------------------------------------------------


class TestCreateTarget:
    async def test_create_then_appears_in_list(self, gvm):
        name = _name()
        result = await create_target(name=name, hosts="10.254.254.1")

        assert not result.get("error"), f"create_target returned error: {result}"
        target_id = result["id"]

        try:
            targets = await list_targets()
            assert isinstance(targets, list)
            ids = [t["id"] for t in targets]
            assert target_id in ids, f"Created target {target_id!r} not found in list_targets"
        finally:
            try:
                gvm.delete_target(target_id=target_id)
            except Exception as exc:
                _log.warning("cleanup failed: could not delete target %r: %s", target_id, exc)

    async def test_empty_name_validation_error(self):
        result = await create_target(name="", hosts="10.254.254.1")
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    async def test_invalid_port_list_uuid_validation_error(self):
        result = await create_target(name=_name(), hosts="10.254.254.1", port_list_id="not-a-uuid")
        assert result.get("error") is True
        assert result["code"] == "validation_error"


# ---------------------------------------------------------------------------
# list_tasks
# ---------------------------------------------------------------------------


class TestListTasks:
    async def test_returns_list(self):
        result = await list_tasks()
        assert isinstance(result, list)

    async def test_each_task_has_expected_keys(self):
        result = await list_tasks()
        for task in result:
            assert "id" in task
            assert "name" in task
            assert "status" in task
            for key in (
                "last_report_date",
                "severity",
                "report_count",
                "finished_report_count",
                "trend",
                "target_id",
                "target_name",
                "host_count",
            ):
                assert key in task
            assert task["severity"] is None or isinstance(task["severity"], float)
            assert task["host_count"] is None or isinstance(task["host_count"], int)

    async def test_last_report_date_is_populated_for_completed_tasks(self):
        """A task that has a last report must expose when that report was made."""
        result = await list_tasks(filter_string="status=Done rows=20")
        with_reports = [t for t in result if t["last_report"]]
        if not with_reports:
            pytest.skip("no completed tasks with a report on this GVM")
        for task in with_reports:
            assert task["last_report_date"]

    async def test_host_count_resolves_for_tasks_with_a_target(self):
        result = await list_tasks(filter_string="rows=20")
        with_targets = [t for t in result if t["target_id"]]
        if not with_targets:
            pytest.skip("no tasks with a target on this GVM")
        assert any(t["host_count"] is not None for t in with_targets)

    async def test_rows_filter_limits_page_size(self):
        result = await list_tasks(filter_string="rows=1")
        assert isinstance(result, list)
        assert len(result) <= 1

    async def test_invalid_filter_returns_validation_error(self):
        result = await list_tasks(filter_string="a" * 1001)
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    async def test_unsupported_filter_keyword_returns_validation_error(self):
        """GVM would drop this term silently and return every task."""
        result = await list_tasks(filter_string="zzzbogus<4")
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    async def test_unparseable_date_value_returns_validation_error(self):
        result = await list_tasks(filter_string="last<yesterday")
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    async def test_compound_filter_narrows_the_result_set(self):
        """The acceptance query: an explicit `and` must intersect, not widen."""
        by_severity = await list_tasks(filter_string="severity>5 rows=-1")
        compound = await list_tasks(filter_string="severity>5 and last<-1M rows=-1")
        assert isinstance(by_severity, list)
        assert isinstance(compound, list)
        assert len(compound) <= len(by_severity)
        for task in compound:
            assert task["severity"] is None or task["severity"] > 5


# ---------------------------------------------------------------------------
# start_task
# ---------------------------------------------------------------------------


class TestStartTask:
    """No test here starts a real scan — only the rejection paths are exercised."""

    async def test_invalid_uuid_returns_validation_error(self):
        result = await start_task(task_id="not-a-uuid")
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    async def test_nonexistent_task_returns_not_found(self):
        result = await start_task(task_id="00000000-0000-0000-0000-000000000000")
        assert result.get("error") is True
        assert result["code"] in ("not_found", "gvm_response_error", "gvm_error")


# ---------------------------------------------------------------------------
# fetch_scan_results
# ---------------------------------------------------------------------------


class TestFetchScanResults:
    async def test_invalid_uuid_returns_validation_error(self):
        result = await fetch_scan_results(task_id="not-a-uuid")
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    async def test_severity_out_of_range_returns_validation_error(self):
        result = await fetch_scan_results(
            task_id="12345678-1234-1234-1234-123456789abc", min_severity=11.0
        )
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    async def test_nonexistent_task_returns_not_found(self):
        result = await fetch_scan_results(task_id="00000000-0000-0000-0000-000000000000")
        assert result.get("error") is True
        assert result["code"] in ("not_found", "gvm_response_error", "gvm_error")
