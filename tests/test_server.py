"""Tests for openvas_mcp.server tool functions."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from openvas_mcp.policy import ClientPolicy, Policy, get_policy, set_policy
from openvas_mcp.server import (
    create_target,
    fetch_scan_results,
    get_scan_status,
    list_targets,
    list_tasks,
    start_scan,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_VALID_UUID = "12345678-1234-1234-1234-123456789abc"
_VALID_UUID2 = "abcdef12-abcd-abcd-abcd-abcdef123456"


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------


class TestElemText:
    def test_none_element_returns_default(self):
        from openvas_mcp.server import _elem_text

        assert _elem_text(None, "name") == ""
        assert _elem_text(None, "name", "fallback") == "fallback"


def _target_xml(
    tid: str = _VALID_UUID, name: str = "test-target", hosts: str = "10.0.0.1"
) -> ET.Element:
    root = ET.fromstring(f"""
    <get_targets_response>
        <target id="{tid}">
            <name>{name}</name>
            <hosts>{hosts}</hosts>
            <port_list><name>All TCP</name></port_list>
        </target>
    </get_targets_response>
    """)
    return root


def _task_xml(tid: str = _VALID_UUID, name: str = "test-task", status: str = "Done") -> ET.Element:
    return ET.fromstring(f"""
    <get_tasks_response>
        <task id="{tid}">
            <name>{name}</name>
            <status>{status}</status>
            <progress>100</progress>
            <last_report><report id="{_VALID_UUID2}"/></last_report>
        </task>
    </get_tasks_response>
    """)


# ---------------------------------------------------------------------------
# list_targets
# ---------------------------------------------------------------------------


class TestListTargets:
    async def test_returns_list(self, gmp_session_mock):
        gmp_session_mock.get_targets.return_value = _target_xml()
        result = await list_targets()
        assert isinstance(result, list)
        assert result[0]["id"] == _VALID_UUID
        assert result[0]["name"] == "test-target"
        assert result[0]["hosts"] == "10.0.0.1"

    async def test_gmp_response_error(self, gmp_session_mock):
        from gvm.errors import GvmResponseError

        gmp_session_mock.get_targets.side_effect = GvmResponseError("400", "bad request")
        result = await list_targets()
        assert result["error"] is True
        assert result["code"] == "gvm_response_error"

    async def test_gmp_server_error(self, gmp_session_mock):
        from gvm.errors import GvmServerError

        gmp_session_mock.get_targets.side_effect = GvmServerError("500", "internal error")
        result = await list_targets()
        assert result["error"] is True
        assert result["code"] == "gvm_server_error"

    async def test_gmp_error_returns_error_dict(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.get_targets.side_effect = GvmError("boom")
        result = await list_targets()
        assert result["error"] is True
        assert result["code"] == "gvm_error"

    async def test_connection_error_returns_error_dict(self, gmp_session_mock):
        gmp_session_mock.get_targets.side_effect = OSError("refused")
        result = await list_targets()
        assert result["error"] is True
        assert result["code"] == "connection_error"


# ---------------------------------------------------------------------------
# create_target
# ---------------------------------------------------------------------------


class TestCreateTarget:
    async def test_success(self, gmp_session_mock):
        resp = ET.fromstring(
            f'<create_target_response id="{_VALID_UUID}" status="201" status_text="OK"/>'
        )
        gmp_session_mock.create_target.return_value = resp
        result = await create_target(name="my-target", hosts="10.0.0.1")
        assert result["id"] == _VALID_UUID
        assert result["status"] == "201"

    async def test_empty_name_validation_error(self, gmp_session_mock):
        result = await create_target(name="   ", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_target.assert_not_called()

    async def test_empty_hosts_validation_error(self, gmp_session_mock):
        result = await create_target(name="target", hosts="")
        assert result["error"] is True
        assert result["code"] == "validation_error"

    async def test_invalid_port_list_uuid_validation_error(self, gmp_session_mock):
        result = await create_target(name="target", hosts="10.0.0.1", port_list_id="not-a-uuid")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_target.assert_not_called()

    async def test_default_port_list_uuid_used_when_empty(self, gmp_session_mock):
        resp = ET.fromstring(
            f'<create_target_response id="{_VALID_UUID}" status="201" status_text="OK"/>'
        )
        gmp_session_mock.create_target.return_value = resp
        await create_target(name="t", hosts="10.0.0.1", port_list_id="")
        _, kwargs = gmp_session_mock.create_target.call_args
        assert kwargs["port_list_id"] == "730ef368-57e2-11e1-a90f-406186ea4fc5"

    async def test_gmp_response_error(self, gmp_session_mock):
        from gvm.errors import GvmResponseError

        gmp_session_mock.create_target.side_effect = GvmResponseError("400", "bad request")
        result = await create_target(name="t", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "gvm_response_error"

    async def test_gmp_server_error(self, gmp_session_mock):
        from gvm.errors import GvmServerError

        gmp_session_mock.create_target.side_effect = GvmServerError("500", "internal error")
        result = await create_target(name="t", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "gvm_server_error"

    async def test_gmp_error_returns_error_dict(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.create_target.side_effect = GvmError("fail")
        result = await create_target(name="t", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "gvm_error"

    async def test_connection_error(self, gmp_session_mock):
        gmp_session_mock.create_target.side_effect = OSError("refused")
        result = await create_target(name="t", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "connection_error"

    async def test_name_too_long_validation_error(self, gmp_session_mock):
        result = await create_target(name="a" * 256, hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_target.assert_not_called()


# ---------------------------------------------------------------------------
# list_tasks
# ---------------------------------------------------------------------------


class TestListTasks:
    async def test_returns_list(self, gmp_session_mock):
        gmp_session_mock.get_tasks.return_value = _task_xml()
        result = await list_tasks()
        assert isinstance(result, list)
        assert result[0]["id"] == _VALID_UUID
        assert result[0]["status"] == "Done"

    async def test_gmp_response_error(self, gmp_session_mock):
        from gvm.errors import GvmResponseError

        gmp_session_mock.get_tasks.side_effect = GvmResponseError("400", "bad request")
        result = await list_tasks()
        assert result["error"] is True
        assert result["code"] == "gvm_response_error"

    async def test_gmp_server_error(self, gmp_session_mock):
        from gvm.errors import GvmServerError

        gmp_session_mock.get_tasks.side_effect = GvmServerError("500", "internal error")
        result = await list_tasks()
        assert result["error"] is True
        assert result["code"] == "gvm_server_error"

    async def test_gmp_error_returns_error_dict(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.get_tasks.side_effect = GvmError("fail")
        result = await list_tasks()
        assert result["error"] is True
        assert result["code"] == "gvm_error"

    async def test_connection_error(self, gmp_session_mock):
        gmp_session_mock.get_tasks.side_effect = OSError("refused")
        result = await list_tasks()
        assert result["error"] is True
        assert result["code"] == "connection_error"


# ---------------------------------------------------------------------------
# start_scan
# ---------------------------------------------------------------------------


class TestStartScan:
    async def test_success(self, gmp_session_mock):
        gmp_session_mock.create_task.return_value = ET.fromstring(
            f'<create_task_response id="{_VALID_UUID}"/>'
        )
        gmp_session_mock.start_task.return_value = ET.fromstring("<start_task_response/>")
        result = await start_scan(name="scan", target_id=_VALID_UUID)
        assert result["task_id"] == _VALID_UUID
        assert result["status"] == "started"

    async def test_empty_name_validation_error(self, gmp_session_mock):
        result = await start_scan(name="", target_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_task.assert_not_called()

    async def test_invalid_target_uuid_validation_error(self, gmp_session_mock):
        result = await start_scan(name="scan", target_id="not-a-uuid")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_task.assert_not_called()

    async def test_invalid_scanner_uuid_validation_error(self, gmp_session_mock):
        result = await start_scan(name="scan", target_id=_VALID_UUID, scanner_id="bad")
        assert result["error"] is True
        assert result["code"] == "validation_error"

    async def test_invalid_scan_config_uuid_validation_error(self, gmp_session_mock):
        result = await start_scan(name="scan", target_id=_VALID_UUID, scan_config_id="bad")
        assert result["error"] is True
        assert result["code"] == "validation_error"

    async def test_gmp_response_error(self, gmp_session_mock):
        from gvm.errors import GvmResponseError

        gmp_session_mock.create_task.side_effect = GvmResponseError("400", "bad request")
        result = await start_scan(name="scan", target_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "gvm_response_error"

    async def test_gmp_server_error(self, gmp_session_mock):
        from gvm.errors import GvmServerError

        gmp_session_mock.create_task.side_effect = GvmServerError("500", "internal error")
        result = await start_scan(name="scan", target_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "gvm_server_error"

    async def test_gmp_error(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.create_task.side_effect = GvmError("fail")
        result = await start_scan(name="scan", target_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "gvm_error"

    async def test_connection_error(self, gmp_session_mock):
        gmp_session_mock.create_task.side_effect = OSError("refused")
        result = await start_scan(name="scan", target_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "connection_error"


# ---------------------------------------------------------------------------
# fetch_scan_results
# ---------------------------------------------------------------------------


class TestFetchScanResults:
    def _make_report_resp(self, severity: float = 5.0) -> ET.Element:
        return ET.fromstring(f"""
        <get_reports_response>
            <report id="{_VALID_UUID2}">
                <results>
                    <result id="{_VALID_UUID}">
                        <name>Test Vuln</name>
                        <host>10.0.0.1</host>
                        <port>80/tcp</port>
                        <severity>{severity}</severity>
                        <threat>Medium</threat>
                        <description>A test finding</description>
                        <nvt><refs><ref type="cve" id="CVE-2024-1234"/></refs></nvt>
                    </result>
                </results>
            </report>
        </get_reports_response>
        """)

    async def test_task_not_found_returns_error_dict(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = ET.fromstring("<get_task_response/>")
        result = await fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "not_found"

    async def test_no_report_returns_error_dict(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = ET.fromstring(f"""
        <get_task_response>
            <task id="{_VALID_UUID}">
                <name>t</name><status>New</status><progress>0</progress>
            </task>
        </get_task_response>
        """)
        result = await fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "not_found"

    def _task_with_report(self):
        return ET.fromstring(f"""
        <get_task_response>
            <task id="{_VALID_UUID}">
                <name>t</name><status>Done</status><progress>100</progress>
                <last_report><report id="{_VALID_UUID2}"/></last_report>
            </task>
        </get_task_response>
        """)

    async def test_results_returned_above_min_severity(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = self._task_with_report()
        gmp_session_mock.get_report.return_value = self._make_report_resp(severity=9.0)
        result = await fetch_scan_results(task_id=_VALID_UUID, min_severity=7.0)
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["severity"] == 9.0

    async def test_severity_filter(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = self._task_with_report()
        gmp_session_mock.get_report.return_value = self._make_report_resp(severity=5.0)
        result = await fetch_scan_results(task_id=_VALID_UUID, min_severity=7.0)
        assert isinstance(result, list)
        assert result == []

    async def test_invalid_severity_text_defaults_to_zero(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = self._task_with_report()
        gmp_session_mock.get_report.return_value = ET.fromstring(f"""
        <get_reports_response>
            <report id="{_VALID_UUID2}">
                <results>
                    <result id="{_VALID_UUID}">
                        <name>Bad Severity</name>
                        <host>10.0.0.1</host><port>80/tcp</port>
                        <severity>not-a-number</severity>
                        <threat>Low</threat><description/>
                    </result>
                </results>
            </report>
        </get_reports_response>
        """)
        result = await fetch_scan_results(task_id=_VALID_UUID, min_severity=0.0)
        assert isinstance(result, list)
        assert result[0]["severity"] == 0.0

    async def test_min_severity_out_of_range(self, gmp_session_mock):
        result = await fetch_scan_results(task_id=_VALID_UUID, min_severity=11.0)
        assert result["error"] is True
        assert result["code"] == "validation_error"

    async def test_invalid_task_uuid(self, gmp_session_mock):
        result = await fetch_scan_results(task_id="not-a-uuid")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.get_task.assert_not_called()

    async def test_gmp_response_error(self, gmp_session_mock):
        from gvm.errors import GvmResponseError

        gmp_session_mock.get_task.side_effect = GvmResponseError("400", "bad request")
        result = await fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "gvm_response_error"

    async def test_gmp_server_error(self, gmp_session_mock):
        from gvm.errors import GvmServerError

        gmp_session_mock.get_task.side_effect = GvmServerError("500", "internal error")
        result = await fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "gvm_server_error"

    async def test_gmp_error(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.get_task.side_effect = GvmError("fail")
        result = await fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "gvm_error"

    async def test_connection_error(self, gmp_session_mock):
        gmp_session_mock.get_task.side_effect = OSError("refused")
        result = await fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "connection_error"


# ---------------------------------------------------------------------------
# get_scan_status
# ---------------------------------------------------------------------------


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    ctx.info = AsyncMock()
    return ctx


class TestGetScanStatus:
    async def test_invalid_uuid_returns_error(self, gmp_session_mock):
        result = await get_scan_status("not-a-uuid", _make_ctx())
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.get_task.assert_not_called()

    async def test_task_not_found(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = ET.fromstring("<get_tasks_response/>")
        result = await get_scan_status(_VALID_UUID, _make_ctx())
        assert result["error"] is True
        assert result["code"] == "not_found"

    async def test_done_returns_immediately(self, gmp_session_mock):
        ctx = _make_ctx()
        gmp_session_mock.get_task.return_value = ET.fromstring(f"""
        <get_tasks_response>
            <task id="{_VALID_UUID}">
                <name>test</name>
                <status>Done</status>
                <progress>100</progress>
            </task>
        </get_tasks_response>
        """)
        result = await get_scan_status(_VALID_UUID, ctx)
        assert result["status"] == "Done"
        ctx.report_progress.assert_called_once_with(100, 100)

    async def test_polls_until_terminal(self, gmp_session_mock):
        ctx = _make_ctx()
        running = ET.fromstring(f"""
        <get_tasks_response>
            <task id="{_VALID_UUID}">
                <name>test</name><status>Running</status><progress>50</progress>
            </task>
        </get_tasks_response>
        """)
        done = ET.fromstring(f"""
        <get_tasks_response>
            <task id="{_VALID_UUID}">
                <name>test</name><status>Done</status><progress>100</progress>
            </task>
        </get_tasks_response>
        """)
        gmp_session_mock.get_task.side_effect = [running, done]

        with patch("asyncio.sleep", new_callable=AsyncMock):
            result = await get_scan_status(_VALID_UUID, ctx)

        assert result["status"] == "Done"
        assert gmp_session_mock.get_task.call_count == 2

    async def test_gvm_error_returns_error(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.get_task.side_effect = GvmError("fail")
        result = await get_scan_status(_VALID_UUID, _make_ctx())
        assert result["error"] is True
        assert result["code"] == "gvm_error"


# ---------------------------------------------------------------------------
# Policy enforcement in tools
# ---------------------------------------------------------------------------


@pytest.fixture
def deny_all_policy():
    """Temporarily set a policy that denies all tools."""
    original = get_policy()
    set_policy(Policy(default_policy=ClientPolicy(allowed_tools=[], allowed_cidrs=[])))
    yield
    set_policy(original)


@pytest.fixture
def cidr_restricted_policy():
    """Temporarily set a policy that only allows 10.0.0.0/8."""
    original = get_policy()
    set_policy(
        Policy(default_policy=ClientPolicy(allowed_tools=["*"], allowed_cidrs=["10.0.0.0/8"]))
    )
    yield
    set_policy(original)


class TestToolAuthzEnforcement:
    async def test_list_targets_denied(self, gmp_session_mock, deny_all_policy):
        result = await list_targets()
        assert result["error"] is True
        assert result["code"] == "forbidden"
        gmp_session_mock.get_targets.assert_not_called()

    async def test_list_tasks_denied(self, gmp_session_mock, deny_all_policy):
        result = await list_tasks()
        assert result["error"] is True
        assert result["code"] == "forbidden"

    async def test_create_target_denied(self, gmp_session_mock, deny_all_policy):
        result = await create_target(name="t", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "forbidden"
        gmp_session_mock.create_target.assert_not_called()

    async def test_start_scan_denied(self, gmp_session_mock, deny_all_policy):
        result = await start_scan(name="scan", target_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "forbidden"
        gmp_session_mock.create_task.assert_not_called()

    async def test_fetch_scan_results_denied(self, gmp_session_mock, deny_all_policy):
        result = await fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "forbidden"
        gmp_session_mock.get_task.assert_not_called()


class TestCreateTargetCIDRPolicy:
    async def test_host_outside_allowed_cidr_denied(self, gmp_session_mock, cidr_restricted_policy):
        result = await create_target(name="t", hosts="192.168.1.1")
        assert result["error"] is True
        assert result["code"] == "forbidden"
        gmp_session_mock.create_target.assert_not_called()

    async def test_host_within_allowed_cidr_permitted(
        self, gmp_session_mock, cidr_restricted_policy
    ):
        resp = ET.fromstring(
            f'<create_target_response id="{_VALID_UUID}" status="201" status_text="OK"/>'
        )
        gmp_session_mock.create_target.return_value = resp
        result = await create_target(name="t", hosts="10.0.0.1")
        assert result["id"] == _VALID_UUID

    async def test_mixed_hosts_denied_if_any_outside_cidr(
        self, gmp_session_mock, cidr_restricted_policy
    ):
        result = await create_target(name="t", hosts="10.0.0.1,192.168.1.1")
        assert result["error"] is True
        assert result["code"] == "forbidden"
        gmp_session_mock.create_target.assert_not_called()


class TestStartScanConcurrentLimit:
    async def test_rate_limited_when_limit_reached(self, gmp_session_mock):
        original = get_policy()
        set_policy(
            Policy(
                default_policy=ClientPolicy(
                    allowed_tools=["*"],
                    allowed_cidrs=["*"],
                    max_concurrent_scans=1,
                )
            )
        )
        try:
            gmp_session_mock.get_tasks.return_value = ET.fromstring(f"""
            <get_tasks_response>
                <task id="{_VALID_UUID}">
                    <name>running</name><status>Running</status><progress>50</progress>
                </task>
            </get_tasks_response>
            """)
            result = await start_scan(name="scan", target_id=_VALID_UUID)
            assert result["error"] is True
            assert result["code"] == "rate_limited"
            gmp_session_mock.create_task.assert_not_called()
        finally:
            set_policy(original)

    async def test_allowed_when_below_limit(self, gmp_session_mock):
        original = get_policy()
        set_policy(
            Policy(
                default_policy=ClientPolicy(
                    allowed_tools=["*"],
                    allowed_cidrs=["*"],
                    max_concurrent_scans=2,
                )
            )
        )
        try:
            gmp_session_mock.get_tasks.return_value = ET.fromstring(f"""
            <get_tasks_response>
                <task id="{_VALID_UUID}">
                    <name>running</name><status>Running</status><progress>50</progress>
                </task>
            </get_tasks_response>
            """)
            gmp_session_mock.create_task.return_value = ET.fromstring(
                f'<create_task_response id="{_VALID_UUID}"/>'
            )
            gmp_session_mock.start_task.return_value = ET.fromstring("<start_task_response/>")
            result = await start_scan(name="scan", target_id=_VALID_UUID)
            assert result["task_id"] == _VALID_UUID
            assert result["status"] == "started"
        finally:
            set_policy(original)
