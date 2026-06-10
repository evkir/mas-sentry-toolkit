# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structured emitters: JSON (machine-readable) + JUnit XML (CI integration)."""

from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import quoteattr

from mas_sentry.core.finding import Finding

_FAILURE_SEVERITIES = {"CRITICAL", "HIGH"}


def write_json(findings: list[Finding], target: str, out_path: Path) -> None:
    payload = {
        "target": target,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "by_severity": _count_by(findings, "severity"),
            "by_module": _count_by(findings, "module"),
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, default=str))


def write_junit(findings: list[Finding], target: str, out_path: Path) -> None:
    """Each Finding becomes a <testcase>; CRITICAL/HIGH register as failures.

    Attribute values use quoteattr (not bare escape) so titles/details that
    contain quotes or angle brackets cannot break the XML.
    """
    failures = sum(1 for f in findings if f.severity.value in _FAILURE_SEVERITIES)
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="mas-sentry" tests="{len(findings)}" failures="{failures}">',
    ]
    for f in findings:
        cls = quoteattr(f.module)
        name = quoteattr(f.title[:200])
        lines.append(f"  <testcase classname={cls} name={name}>")
        if f.severity.value in _FAILURE_SEVERITIES:
            ftype = quoteattr(f.severity.value)
            fmsg = quoteattr(f.detail[:500])
            lines.append(f"    <failure type={ftype} message={fmsg}/>")
        lines.append("  </testcase>")
    lines.append("</testsuite>")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))


def _count_by(findings: list[Finding], attr: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        v = getattr(f, attr)
        key = v.value if hasattr(v, "value") else str(v)
        counts[key] = counts.get(key, 0) + 1
    return counts
