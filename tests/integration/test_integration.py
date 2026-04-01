"""Integration tests — exercise MCP tools against a live GVM instance.

Run with:
    GVM_INTEGRATION=1 GVM_HOST=127.0.0.1 GVM_PORT=9393 GVM_PASSWORD=admin \
        pytest tests/integration/ -v

The Greenbone stack (docker/openvas/compose.yaml) exposes gvmd via the
gvmd-socket-proxy service on port 9393. That's the default for CI.
"""

from __future__ import annotations

import logging
import uuid

from openvas_mcp.server import (
    create_target,
    fetch_scan_results,
    list_targets,
    list_tasks,
)


_PREFIX = "mcp-integration-"
_log = logging.getLogger(__name__)


def _name() -> str:
    return f"{_PREFIX}{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# list_targets
# ---------------------------------------------------------------------------


class TestListTargets:
    def test_returns_list(self):
        result = list_targets()
        assert isinstance(result, list)

    def test_each_target_has_expected_keys(self):
        result = list_targets()
        for target in result:
            assert "id" in target
            assert "name" in target
            assert "hosts" in target


# ---------------------------------------------------------------------------
# create_target
# ---------------------------------------------------------------------------


class TestCreateTarget:
    def test_create_then_appears_in_list(self, gvm):
        name = _name()
        result = create_target(name=name, hosts="10.254.254.1")

        assert not result.get("error"), f"create_target returned error: {result}"
        target_id = result["id"]

        try:
            targets = list_targets()
            assert isinstance(targets, list)
            ids = [t["id"] for t in targets]
            assert target_id in ids, f"Created target {target_id!r} not found in list_targets"
        finally:
            try:
                gvm.delete_target(target_id=target_id)
            except Exception as exc:
                _log.warning("cleanup failed: could not delete target %r: %s", target_id, exc)

    def test_empty_name_validation_error(self):
        result = create_target(name="", hosts="10.254.254.1")
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    def test_invalid_port_list_uuid_validation_error(self):
        result = create_target(name=_name(), hosts="10.254.254.1", port_list_id="not-a-uuid")
        assert result.get("error") is True
        assert result["code"] == "validation_error"


# ---------------------------------------------------------------------------
# list_tasks
# ---------------------------------------------------------------------------


class TestListTasks:
    def test_returns_list(self):
        result = list_tasks()
        assert isinstance(result, list)

    def test_each_task_has_expected_keys(self):
        result = list_tasks()
        for task in result:
            assert "id" in task
            assert "name" in task
            assert "status" in task


# ---------------------------------------------------------------------------
# fetch_scan_results
# ---------------------------------------------------------------------------


class TestFetchScanResults:
    def test_invalid_uuid_returns_validation_error(self):
        result = fetch_scan_results(task_id="not-a-uuid")
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    def test_severity_out_of_range_returns_validation_error(self):
        result = fetch_scan_results(
            task_id="12345678-1234-1234-1234-123456789abc", min_severity=11.0
        )
        assert result.get("error") is True
        assert result["code"] == "validation_error"

    def test_nonexistent_task_returns_not_found(self):
        result = fetch_scan_results(task_id="00000000-0000-0000-0000-000000000000")
        assert result.get("error") is True
        assert result["code"] in ("not_found", "gvm_response_error", "gvm_error")
