"""Tests for openvas_mcp.server tool functions."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from openvas_mcp.server import (
    create_target,
    fetch_scan_results,
    list_targets,
    list_tasks,
    start_scan,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_VALID_UUID = "12345678-1234-1234-1234-123456789abc"
_VALID_UUID2 = "abcdef12-abcd-abcd-abcd-abcdef123456"


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
    def test_returns_list(self, gmp_session_mock):
        gmp_session_mock.get_targets.return_value = _target_xml()
        result = list_targets()
        assert isinstance(result, list)
        assert result[0]["id"] == _VALID_UUID
        assert result[0]["name"] == "test-target"
        assert result[0]["hosts"] == "10.0.0.1"

    def test_gmp_error_returns_error_dict(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.get_targets.side_effect = GvmError("boom")
        result = list_targets()
        assert result["error"] is True
        assert result["code"] == "gvm_error"

    def test_connection_error_returns_error_dict(self, gmp_session_mock):
        gmp_session_mock.get_targets.side_effect = OSError("refused")
        result = list_targets()
        assert result["error"] is True
        assert result["code"] == "connection_error"


# ---------------------------------------------------------------------------
# create_target
# ---------------------------------------------------------------------------


class TestCreateTarget:
    def test_success(self, gmp_session_mock):
        resp = ET.fromstring(
            f'<create_target_response id="{_VALID_UUID}" status="201" status_text="OK"/>'
        )
        gmp_session_mock.create_target.return_value = resp
        result = create_target(name="my-target", hosts="10.0.0.1")
        assert result["id"] == _VALID_UUID
        assert result["status"] == "201"

    def test_empty_name_validation_error(self, gmp_session_mock):
        result = create_target(name="   ", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_target.assert_not_called()

    def test_empty_hosts_validation_error(self, gmp_session_mock):
        result = create_target(name="target", hosts="")
        assert result["error"] is True
        assert result["code"] == "validation_error"

    def test_invalid_port_list_uuid_validation_error(self, gmp_session_mock):
        result = create_target(name="target", hosts="10.0.0.1", port_list_id="not-a-uuid")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_target.assert_not_called()

    def test_default_port_list_uuid_used_when_empty(self, gmp_session_mock):
        resp = ET.fromstring(
            f'<create_target_response id="{_VALID_UUID}" status="201" status_text="OK"/>'
        )
        gmp_session_mock.create_target.return_value = resp
        create_target(name="t", hosts="10.0.0.1", port_list_id="")
        _, kwargs = gmp_session_mock.create_target.call_args
        assert kwargs["port_list_id"] == "730ef368-57e2-11e1-a90f-406186ea4fc5"

    def test_gmp_error_returns_error_dict(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.create_target.side_effect = GvmError("fail")
        result = create_target(name="t", hosts="10.0.0.1")
        assert result["error"] is True
        assert result["code"] == "gvm_error"


# ---------------------------------------------------------------------------
# list_tasks
# ---------------------------------------------------------------------------


class TestListTasks:
    def test_returns_list(self, gmp_session_mock):
        gmp_session_mock.get_tasks.return_value = _task_xml()
        result = list_tasks()
        assert isinstance(result, list)
        assert result[0]["id"] == _VALID_UUID
        assert result[0]["status"] == "Done"

    def test_gmp_error_returns_error_dict(self, gmp_session_mock):
        from gvm.errors import GvmError

        gmp_session_mock.get_tasks.side_effect = GvmError("fail")
        result = list_tasks()
        assert result["error"] is True
        assert result["code"] == "gvm_error"


# ---------------------------------------------------------------------------
# start_scan
# ---------------------------------------------------------------------------


class TestStartScan:
    def test_success(self, gmp_session_mock):
        gmp_session_mock.create_task.return_value = ET.fromstring(
            f'<create_task_response id="{_VALID_UUID}"/>'
        )
        gmp_session_mock.start_task.return_value = ET.fromstring("<start_task_response/>")
        result = start_scan(name="scan", target_id=_VALID_UUID)
        assert result["task_id"] == _VALID_UUID
        assert result["status"] == "started"

    def test_empty_name_validation_error(self, gmp_session_mock):
        result = start_scan(name="", target_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_task.assert_not_called()

    def test_invalid_target_uuid_validation_error(self, gmp_session_mock):
        result = start_scan(name="scan", target_id="not-a-uuid")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.create_task.assert_not_called()

    def test_invalid_scanner_uuid_validation_error(self, gmp_session_mock):
        result = start_scan(name="scan", target_id=_VALID_UUID, scanner_id="bad")
        assert result["error"] is True
        assert result["code"] == "validation_error"

    def test_invalid_scan_config_uuid_validation_error(self, gmp_session_mock):
        result = start_scan(name="scan", target_id=_VALID_UUID, scan_config_id="bad")
        assert result["error"] is True
        assert result["code"] == "validation_error"


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

    def test_task_not_found_returns_error_dict(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = ET.fromstring("<get_task_response/>")
        result = fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "not_found"

    def test_no_report_returns_error_dict(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = ET.fromstring(f"""
        <get_task_response>
            <task id="{_VALID_UUID}">
                <name>t</name><status>New</status><progress>0</progress>
            </task>
        </get_task_response>
        """)
        result = fetch_scan_results(task_id=_VALID_UUID)
        assert result["error"] is True
        assert result["code"] == "not_found"

    def test_severity_filter(self, gmp_session_mock):
        gmp_session_mock.get_task.return_value = ET.fromstring(f"""
        <get_task_response>
            <task id="{_VALID_UUID}">
                <name>t</name><status>Done</status><progress>100</progress>
                <last_report><report id="{_VALID_UUID2}"/></last_report>
            </task>
        </get_task_response>
        """)
        gmp_session_mock.get_report.return_value = self._make_report_resp(severity=5.0)
        result = fetch_scan_results(task_id=_VALID_UUID, min_severity=7.0)
        # The result with severity 5.0 should be filtered out client-side
        assert isinstance(result, list)
        assert all(r["severity"] >= 7.0 for r in result)

    def test_min_severity_out_of_range(self, gmp_session_mock):
        result = fetch_scan_results(task_id=_VALID_UUID, min_severity=11.0)
        assert result["error"] is True
        assert result["code"] == "validation_error"

    def test_invalid_task_uuid(self, gmp_session_mock):
        result = fetch_scan_results(task_id="not-a-uuid")
        assert result["error"] is True
        assert result["code"] == "validation_error"
        gmp_session_mock.get_task.assert_not_called()

    # get_scan_status is excluded from unit tests — it requires
    # asyncio.to_thread, a Context object, and pytest-asyncio scaffolding.
    # TODO: add async tool tests when pytest-asyncio is introduced.
