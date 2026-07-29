# SPDX-License-Identifier: AGPL-3.0-or-later
"""`report convert` has to recognise the shape the MCP scan actually writes.

`mas-sentry mcp scan --out` produces {check, severity, detail} rows, not unified
Findings. The adapter that maps them - synthesizing a title and attaching the
ASI/CWE/STRIDE/ATLAS tags for the check - existed and was unit-tested from the
start, but nothing in the product called it, so every MCP finding reached HTML,
Markdown, SARIF and JUnit as module `unknown` with an empty title and no
taxonomy. These tests exercise the CLI path rather than the adapter, which is
the distinction that let the defect live.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mas_sentry.cli import app

runner = CliRunner()

_MCP_SCAN_ROWS = [
    {"check": "fingerprint", "severity": "INFO", "detail": "vuln-mcp-ref 0.1.0 (4 tools)"},
    {
        "check": "tool_poisoning",
        "severity": "CRITICAL",
        "detail": "search_notes: Suspicious patterns in tool description",
    },
]


def _scan_file(path: Path) -> Path:
    path.write_text(json.dumps(_MCP_SCAN_ROWS), encoding="utf-8")
    return path


def _convert(src: Path, out: Path, fmt: str) -> None:
    result = runner.invoke(
        app,
        ["report", "convert", str(src), "-f", fmt, "-o", str(out), "--target", "rig"],
    )
    assert result.exit_code == 0, result.output


def test_mcp_rows_keep_their_module_and_title(tmp_path: Path) -> None:
    """`unknown` with a blank title is what an operator used to read."""
    out = tmp_path / "out.json"
    _convert(_scan_file(tmp_path / "mcp.json"), out, "json")
    findings = json.loads(out.read_text())["findings"]

    modules = {f["module"] for f in findings}
    assert modules == {"mcp.fingerprint", "mcp.tool_poisoning"}
    assert all(f["title"] for f in findings)


def test_mcp_rows_carry_their_taxonomy(tmp_path: Path) -> None:
    """The tag table is the reason the adapter exists; it has to be applied."""
    out = tmp_path / "out.json"
    _convert(_scan_file(tmp_path / "mcp.json"), out, "json")
    findings = json.loads(out.read_text())["findings"]

    poisoning = next(f for f in findings if f["module"] == "mcp.tool_poisoning")
    assert {"ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"} <= set(poisoning["tags"])


def test_sarif_rules_are_named_after_the_check(tmp_path: Path) -> None:
    """A CRITICAL hit filed under ruleId `unknown` is unusable in code scanning."""
    out = tmp_path / "out.sarif"
    _convert(_scan_file(tmp_path / "mcp.json"), out, "sarif")
    rules = {r["id"] for r in json.loads(out.read_text())["runs"][0]["tool"]["driver"]["rules"]}

    assert "MAS-SENTRY-MCP.TOOL_POISONING" in rules
    assert not any("UNKNOWN" in r for r in rules)


def test_unified_findings_are_not_routed_through_the_mcp_adapter(tmp_path: Path) -> None:
    """A row that already carries `module` is a unified Finding and stays one."""
    src = tmp_path / "unified.json"
    src.write_text(
        json.dumps([{"module": "a2a.card_audit", "title": "kept", "detail": "d", "severity": "HIGH", "tags": ["a2a"]}]),
        encoding="utf-8",
    )
    out = tmp_path / "out.json"
    _convert(src, out, "json")
    finding = json.loads(out.read_text())["findings"][0]

    assert finding["module"] == "a2a.card_audit"
    assert finding["title"] == "kept"
    assert finding["tags"] == ["a2a"]
