# SPDX-License-Identifier: AGPL-3.0-or-later
"""Smoke + security tests for all report renderers."""

import json
from pathlib import Path
from xml.dom.minidom import parseString

from mas_sentry.core.finding import Finding, Severity
from mas_sentry.reporting.markdown import render_markdown
from mas_sentry.reporting.structured import write_json, write_junit
from mas_sentry.reporting.unified_html import render_unified_html


def _sample() -> list[Finding]:
    return [
        Finding(
            module="mcp.ssrf",
            title="SSRF to IMDS",
            detail="agent fetched cloud metadata",
            severity=Severity.CRITICAL,
            target="lab",
            tags=["ASI02_Tool_Misuse", "CWE-918"],
            evidence={"url": "http://169.254.169.254/"},
        ),
        Finding(
            module="abfp.rogue",
            title="Unknown agent",
            detail="agent absent from baseline",
            severity=Severity.HIGH,
            target="lab",
            tags=["ASI10_Rogue_Agent"],
        ),
        Finding(
            module="agentic.supply_chain",
            title="Floating deps",
            detail="requirements not pinned",
            severity=Severity.MEDIUM,
            target="lab",
            tags=["ASI04_Supply_Chain"],
        ),
    ]


# ─────────────── HTML ───────────────


def test_html_renderer_writes_file(tmp_path: Path) -> None:
    out = tmp_path / "r.html"
    render_unified_html(_sample(), "lab", out)
    assert out.exists()
    content = out.read_text()
    assert "MAS-Sentry Audit Report" in content
    assert "SSRF to IMDS" in content
    assert "ASI02_Tool_Misuse" in content


def test_html_escapes_xss_in_title(tmp_path: Path) -> None:
    out = tmp_path / "xss.html"
    payload = "<script>alert('xss')</script>"
    findings = [
        Finding(
            module="m",
            title=payload,
            detail="d",
            severity=Severity.HIGH,
            target="lab",
        )
    ]
    render_unified_html(findings, "lab", out)
    html = out.read_text()
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_html_escapes_xss_in_target(tmp_path: Path) -> None:
    out = tmp_path / "xss2.html"
    render_unified_html([], "<svg onload=alert(1)>", out)
    html = out.read_text()
    assert "<svg onload" not in html


def test_html_empty_findings_still_valid(tmp_path: Path) -> None:
    out = tmp_path / "empty.html"
    render_unified_html([], "lab", out)
    html = out.read_text()
    assert "MAS-Sentry Audit Report" in html
    # max severity of empty list is INFO
    assert "sev-INFO" in html


# ─────────────── Markdown ───────────────


def test_markdown_renderer_includes_all(tmp_path: Path) -> None:
    out = tmp_path / "r.md"
    render_markdown(_sample(), "lab", out)
    text = out.read_text()
    assert "# MAS-Sentry Audit - lab" in text
    assert "CRITICAL: 1" in text
    assert "SSRF to IMDS" in text


def test_markdown_summary_table_and_detail(tmp_path: Path) -> None:
    out = tmp_path / "r.md"
    render_markdown(_sample(), "lab", out)
    text = out.read_text()
    assert "| # | Severity | Module | Title |" in text
    assert "### 1. SSRF to IMDS" in text
    assert "```json" in text  # evidence block for finding 1


def test_markdown_empty_findings(tmp_path: Path) -> None:
    out = tmp_path / "empty.md"
    render_markdown([], "lab", out)
    text = out.read_text()
    assert "**Findings:** 0" in text


# ─────────────── JSON ───────────────


def test_json_renderer_summary(tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    write_json(_sample(), "lab", out)
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 3
    assert data["summary"]["by_severity"]["CRITICAL"] == 1
    assert data["summary"]["by_module"]["mcp.ssrf"] == 1


# ─────────────── JUnit ───────────────


def test_junit_renderer_failures_count(tmp_path: Path) -> None:
    out = tmp_path / "r.xml"
    write_junit(_sample(), "lab", out)
    text = out.read_text()
    assert 'failures="2"' in text  # CRITICAL + HIGH
    assert "<testcase" in text


def test_junit_is_valid_xml(tmp_path: Path) -> None:
    out = tmp_path / "r.xml"
    write_junit(_sample(), "lab", out)
    dom = parseString(out.read_text())
    assert len(dom.getElementsByTagName("testcase")) == 3
    assert len(dom.getElementsByTagName("failure")) == 2


def test_junit_neutralises_xml_injection(tmp_path: Path) -> None:
    out = tmp_path / "evil.xml"
    findings = [
        Finding(
            module="m",
            title='"><inject/>break',
            detail='detail with "quotes" and <tags>',
            severity=Severity.CRITICAL,
            target="lab",
        )
    ]
    write_junit(findings, "lab", out)
    dom = parseString(out.read_text())  # raises if injection broke the XML
    tc = dom.getElementsByTagName("testcase")[0]
    assert tc.getAttribute("name") == '"><inject/>break'


def test_unified_html_renders_drivers(tmp_path: Path) -> None:
    f = Finding(
        module="abfp.rogue",
        title="Rogue agent: agent-7",
        detail="drift",
        severity=Severity.HIGH,
        target="demo",
        evidence={
            "agent_id": "agent-7",
            "dimensions": [
                {"name": "timing", "raw": 0.61, "reason": "interval variance"},
                {"name": "identity", "raw": 0.9, "reason": "<img src=x onerror=alert(1)>"},
            ],
        },
    )
    out = tmp_path / "r.html"
    render_unified_html([f], "demo", out)
    html = out.read_text()
    assert 'class="drivers"' in html
    assert "timing" in html and "identity" in html
    assert "0.61" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img" in html
