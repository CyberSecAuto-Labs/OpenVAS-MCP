"""Apply the release-line filter to a grype JSON report and gate on severity.

grype reports a CVE as "fixed" even when the only fix landed on a release line
we do not ship. The image runs CPython 3.11, so a CVE fixed exclusively in
3.13.x/3.14.x is real but not actionable — no rebuild of `python:3.11-slim` can
clear it, and there is nothing to upgrade to short of leaving the supported
Python range.

Listing those CVEs individually in `.grype.yaml` means a new entry every few
weeks. Instead, this gate suppresses a `python` binary finding when none of its
fix versions land on the release line the image actually runs. The line is read
from the SBOM rather than hardcoded, so moving the base image to a newer Python
re-evaluates every finding against that line automatically.

A CVE fixed in 3.11.16 still fails the gate: it is on our line and a rebuild
clears it. That is the signal the scan exists to produce.

Usage:
    python3 scripts/grype_gate.py <report.json> [--fail-on high]
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

# grype severity labels, ascending. Anything unrecognised sorts above the top
# of this list so an unknown label can never silently pass the gate.
SEVERITY_ORDER = ["negligible", "low", "medium", "high", "critical"]

# Package the release-line filter applies to. Deliberately narrow: it encodes a
# fact about CPython's branch-based backporting, not a general rule about base
# image packages.
FILTERED_NAME = "python"
FILTERED_TYPE = "binary"


def severity_rank(severity: str) -> int:
    """Rank a grype severity label; unknown labels rank highest (fail closed)."""
    try:
        return SEVERITY_ORDER.index(severity.strip().lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def release_line(version: str) -> str | None:
    """Reduce a version to its `major.minor` release line.

    Handles pre-release suffixes on the patch component (`3.14.5rc1`,
    `3.15.0b2`). Returns None if the version has no usable major.minor.
    """
    parts = version.strip().lstrip("v").split(".")
    if len(parts) < 2:
        return None
    major, minor = parts[0], parts[1]
    # A pre-release marker can sit on the minor component (e.g. "3.15rc1").
    minor_digits = ""
    for char in minor:
        if not char.isdigit():
            break
        minor_digits += char
    if not major.isdigit() or not minor_digits:
        return None
    return f"{major}.{minor_digits}"


def is_out_of_line(match: dict[str, Any]) -> bool:
    """True if this is a python binary finding with no fix on the installed line."""
    artifact = match.get("artifact") or {}
    if artifact.get("name") != FILTERED_NAME or artifact.get("type") != FILTERED_TYPE:
        return False

    installed_line = release_line(artifact.get("version") or "")
    if installed_line is None:
        # Cannot determine what we are running; do not suppress anything.
        return False

    fix_versions = ((match.get("vulnerability") or {}).get("fix") or {}).get("versions") or []
    if not fix_versions:
        # Nothing to compare against — leave the finding for the severity gate.
        return False

    return all(release_line(v) != installed_line for v in fix_versions)


def describe(match: dict[str, Any]) -> str:
    vuln = match.get("vulnerability") or {}
    artifact = match.get("artifact") or {}
    fixes = ", ".join((vuln.get("fix") or {}).get("versions") or []) or "none"
    return (
        f"{vuln.get('id', '?'):<18} {vuln.get('severity', '?'):<11} "
        f"{artifact.get('name', '?')} {artifact.get('version', '?')}  fixed in: {fixes}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="Path to a grype JSON report")
    parser.add_argument(
        "--fail-on",
        default="high",
        help="Minimum severity that fails the gate (default: high)",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.report, encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        # Fail closed: an unreadable report must never look like a clean scan.
        print(f"error: cannot read grype report {args.report}: {exc}", file=sys.stderr)
        return 2

    if not isinstance(report, dict) or "matches" not in report:
        print(
            f"error: {args.report} is not a grype JSON report (no 'matches' key)",
            file=sys.stderr,
        )
        return 2

    threshold = severity_rank(args.fail_on)
    if threshold >= len(SEVERITY_ORDER):
        print(f"error: unknown --fail-on severity {args.fail_on!r}", file=sys.stderr)
        return 2

    suppressed = []
    remaining = []
    for match in report["matches"]:
        (suppressed if is_out_of_line(match) else remaining).append(match)

    blocking = [
        m
        for m in remaining
        if severity_rank((m.get("vulnerability") or {}).get("severity") or "") >= threshold
    ]

    if suppressed:
        print(
            f"Suppressed {len(suppressed)} {FILTERED_NAME} finding(s) with no fix on "
            "the installed release line:"
        )
        for match in sorted(suppressed, key=lambda m: m["vulnerability"].get("id", "")):
            print(f"  {describe(match)}")
        print()

    if blocking:
        print(f"Findings at or above '{args.fail_on}':")
        for match in sorted(blocking, key=lambda m: m["vulnerability"].get("id", "")):
            print(f"  {describe(match)}")
        print(f"\nFAIL: {len(blocking)} finding(s) at or above '{args.fail_on}'.")
        return 1

    print(
        f"PASS: no findings at or above '{args.fail_on}' "
        f"({len(remaining)} finding(s) below threshold, {len(suppressed)} suppressed)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
