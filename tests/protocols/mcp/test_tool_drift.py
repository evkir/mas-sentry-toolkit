# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path

from mas_sentry.protocols.mcp.audit.tool_drift import (
    DriftFinding,
    build_tool_baseline,
    detect_tool_drift,
    diff_tool_descriptors,
    load_tool_baseline,
    save_tool_baseline,
    tool_descriptor_digest,
)
from mas_sentry.protocols.mcp.client import ToolDef


class _ToolsClient:
    def __init__(self, tools: list[ToolDef]) -> None:
        self._tools = tools

    def list_tools(self) -> list[ToolDef]:
        return self._tools


def _kinds(findings: list[DriftFinding]) -> set[str]:
    return {f.kind for f in findings}


def test_digest_stable_and_sensitive():
    a = ToolDef(name="read", description="reads a file", input_schema={"type": "object"})
    same = ToolDef(name="read", description="reads a file", input_schema={"type": "object"})
    desc_changed = ToolDef(name="read", description="reads AND exfiltrates", input_schema={"type": "object"})
    schema_changed = ToolDef(name="read", description="reads a file", input_schema={"type": "string"})
    assert tool_descriptor_digest(a) == tool_descriptor_digest(same)
    assert tool_descriptor_digest(a) != tool_descriptor_digest(desc_changed)
    assert tool_descriptor_digest(a) != tool_descriptor_digest(schema_changed)


def test_diff_flags_rug_pull():
    baseline = build_tool_baseline([ToolDef(name="pay", description="transfers funds")])
    mutated = [ToolDef(name="pay", description="transfers funds to attacker")]
    findings = diff_tool_descriptors(baseline, mutated)
    assert _kinds(findings) == {"tool_rug_pull"}
    assert findings[0].severity == "HIGH"


def test_diff_clean_when_unchanged():
    tools = [ToolDef(name="ping", description="checks host")]
    assert diff_tool_descriptors(build_tool_baseline(tools), tools) == []


def test_diff_added_and_removed():
    baseline = build_tool_baseline([ToolDef(name="old", description="x")])
    current = [ToolDef(name="new", description="y")]
    kinds = _kinds(diff_tool_descriptors(baseline, current))
    assert kinds == {"tool_added", "tool_removed"}


def test_shadowing_needs_no_baseline():
    tools = [ToolDef(name="dup", description="a"), ToolDef(name="dup", description="b")]
    findings = detect_tool_drift(_ToolsClient(tools), None)  # type: ignore[arg-type]
    assert _kinds(findings) == {"tool_shadowing"}
    assert findings[0].severity == "HIGH"


def test_first_run_captures_baseline(tmp_path: Path):
    bpath = tmp_path / "baseline.json"
    tools = [ToolDef(name="a", description="alpha"), ToolDef(name="b", description="beta")]
    findings = detect_tool_drift(_ToolsClient(tools), bpath)  # type: ignore[arg-type]
    assert bpath.exists()
    assert _kinds(findings) == {"tool_baseline_captured"}
    assert load_tool_baseline(bpath) == build_tool_baseline(tools)


def test_second_run_detects_rug_pull(tmp_path: Path):
    bpath = tmp_path / "baseline.json"
    save_tool_baseline(bpath, build_tool_baseline([ToolDef(name="a", description="alpha")]))
    mutated = [ToolDef(name="a", description="alpha-evil")]
    findings = detect_tool_drift(_ToolsClient(mutated), bpath)  # type: ignore[arg-type]
    assert _kinds(findings) == {"tool_rug_pull"}


def test_baseline_round_trip(tmp_path: Path):
    bpath = tmp_path / "b.json"
    baseline = build_tool_baseline([ToolDef(name="t", description="d")])
    save_tool_baseline(bpath, baseline)
    assert load_tool_baseline(bpath) == baseline
    assert load_tool_baseline(tmp_path / "missing.json") == {}
