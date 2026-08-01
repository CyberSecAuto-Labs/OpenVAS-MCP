"""Tests for scripts/grype_gate.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "scripts" / "grype_gate.py"
_spec = importlib.util.spec_from_file_location("grype_gate", _MODULE_PATH)
assert _spec is not None and _spec.loader is not None
grype_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(grype_gate)


def make_match(vuln_id, severity, name, version, fix_versions, pkg_type="binary"):
    return {
        "vulnerability": {
            "id": vuln_id,
            "severity": severity,
            "fix": {"versions": list(fix_versions), "state": "fixed"},
        },
        "artifact": {"name": name, "version": version, "type": pkg_type},
    }


def write_report(tmp_path, matches):
    path = tmp_path / "grype.json"
    path.write_text(json.dumps({"matches": matches}), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize(
    "version,expected",
    [
        ("3.11.15", "3.11"),
        ("3.13.14", "3.13"),
        ("3.14.5rc1", "3.14"),
        ("3.15.0b2", "3.15"),
        ("3.11", "3.11"),
        ("v3.12.1", "3.12"),
        ("3", None),
        ("", None),
        ("notaversion", None),
    ],
)
def test_release_line(version, expected):
    assert grype_gate.release_line(version) == expected


def test_severity_rank_orders_ascending():
    assert grype_gate.severity_rank("negligible") < grype_gate.severity_rank("high")
    assert grype_gate.severity_rank("high") < grype_gate.severity_rank("critical")
    assert grype_gate.severity_rank("High") == grype_gate.severity_rank("high")


def test_unknown_severity_ranks_above_all_known():
    """An unrecognised label must never sort below the threshold and slip through."""
    assert grype_gate.severity_rank("bogus") > grype_gate.severity_rank("critical")


def test_suppresses_python_finding_fixed_only_on_other_lines():
    match = make_match(
        "CVE-2026-7210", "High", "python", "3.11.15", ["3.13.14", "3.14.6", "3.15.0b2"]
    )
    assert grype_gate.is_out_of_line(match) is True


def test_keeps_python_finding_fixed_on_installed_line():
    """The signal the gate exists to preserve: a fix we can actually pick up."""
    match = make_match("CVE-2099-0001", "High", "python", "3.11.15", ["3.11.16", "3.13.1"])
    assert grype_gate.is_out_of_line(match) is False


def test_keeps_non_python_findings():
    match = make_match("GHSA-xxxx", "High", "jaraco-context", "5.3.0", ["6.1.0"], pkg_type="python")
    assert grype_gate.is_out_of_line(match) is False


def test_keeps_python_package_named_python_that_is_not_a_binary():
    match = make_match("CVE-1", "High", "python", "3.11.15", ["3.13.1"], pkg_type="python")
    assert grype_gate.is_out_of_line(match) is False


def test_keeps_finding_with_no_fix_versions():
    match = make_match("CVE-2", "High", "python", "3.11.15", [])
    assert grype_gate.is_out_of_line(match) is False


def test_keeps_finding_when_installed_version_unparseable():
    match = make_match("CVE-3", "High", "python", "unknown", ["3.13.1"])
    assert grype_gate.is_out_of_line(match) is False


def test_release_line_follows_base_image_upgrade():
    """On a 3.13 base image, a 3.13.14 fix becomes actionable and must not suppress."""
    match = make_match("CVE-2026-7210", "High", "python", "3.13.2", ["3.13.14", "3.14.6"])
    assert grype_gate.is_out_of_line(match) is False


def test_main_passes_when_only_suppressed_findings(tmp_path, capsys):
    report = write_report(
        tmp_path,
        [make_match("CVE-A", "High", "python", "3.11.15", ["3.13.14"])],
    )
    assert grype_gate.main([report, "--fail-on", "high"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_main_fails_on_actionable_high(tmp_path, capsys):
    report = write_report(
        tmp_path,
        [
            make_match("CVE-A", "High", "python", "3.11.15", ["3.13.14"]),
            make_match("GHSA-b", "High", "wheel", "0.45.1", ["0.46.2"], pkg_type="python"),
        ],
    )
    assert grype_gate.main([report, "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "GHSA-b" in out
    assert "FAIL" in out


def test_main_ignores_findings_below_threshold(tmp_path):
    report = write_report(
        tmp_path,
        [make_match("GHSA-b", "Medium", "wheel", "0.45.1", ["0.46.2"], pkg_type="python")],
    )
    assert grype_gate.main([report, "--fail-on", "high"]) == 0


def test_main_fails_closed_on_missing_report(tmp_path):
    assert grype_gate.main([str(tmp_path / "nope.json"), "--fail-on", "high"]) == 2


def test_main_fails_closed_on_malformed_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert grype_gate.main([str(path), "--fail-on", "high"]) == 2


def test_main_fails_closed_on_non_grype_json(tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"unrelated": True}), encoding="utf-8")
    assert grype_gate.main([str(path), "--fail-on", "high"]) == 2


def test_main_rejects_unknown_fail_on_severity(tmp_path):
    report = write_report(tmp_path, [])
    assert grype_gate.main([report, "--fail-on", "bogus"]) == 2
