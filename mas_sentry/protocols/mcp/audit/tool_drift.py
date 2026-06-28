# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP tool-descriptor drift detection (rug-pull / shadowing).

Captures a baseline digest of each tool's descriptor (description plus input
schema) keyed by tool name, then on a later scan flags:

- tool_rug_pull: an existing tool whose descriptor mutated after the baseline
  was captured -- the classic post-approval rug pull that most MCP clients do
  not detect;
- tool_shadowing: two or more tools advertising the same name within a single
  enumeration;
- tool_added / tool_removed: tools appearing or disappearing relative to the
  baseline.

The baseline is a plain ``{tool_name: digest}`` JSON map, intended to be
committed alongside a project so CI can diff descriptors on every run.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ..client import McpClient, ToolDef


@dataclass(frozen=True, slots=True)
class DriftFinding:
    tool: str
    kind: str  # tool_rug_pull / tool_shadowing / tool_added / tool_removed / tool_baseline_captured
    severity: str
    detail: str


def tool_descriptor_digest(tool: ToolDef) -> str:
    """Stable SHA-256 over a tool's security-relevant descriptor surface."""
    canonical = json.dumps(
        {"description": tool.description, "input_schema": tool.input_schema},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()


def build_tool_baseline(tools: list[ToolDef]) -> dict[str, str]:
    """Map each tool name to its descriptor digest (last write wins on duplicates)."""
    return {t.name: tool_descriptor_digest(t) for t in tools}


def load_tool_baseline(path: Path) -> dict[str, str]:
    """Load a baseline digest map; empty dict if the file is absent."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {str(k): str(v) for k, v in data.items()}


def save_tool_baseline(path: Path, baseline: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(baseline, indent=2, sort_keys=True))


def _shadowing_findings(tools: list[ToolDef]) -> list[DriftFinding]:
    counts = Counter(t.name for t in tools)
    return [
        DriftFinding(
            tool=name,
            kind="tool_shadowing",
            severity="HIGH",
            detail=f"{count} tools advertise the name '{name}' in one enumeration",
        )
        for name, count in sorted(counts.items())
        if count > 1
    ]


def diff_tool_descriptors(baseline: dict[str, str], tools: list[ToolDef]) -> list[DriftFinding]:
    """Compare current tools against a prior baseline digest map."""
    findings = _shadowing_findings(tools)
    current = build_tool_baseline(tools)

    for name, digest in current.items():
        prior = baseline.get(name)
        if prior is not None and prior != digest:
            findings.append(
                DriftFinding(
                    tool=name,
                    kind="tool_rug_pull",
                    severity="HIGH",
                    detail=f"Descriptor for '{name}' changed since baseline (post-approval mutation)",
                )
            )
        elif prior is None:
            findings.append(
                DriftFinding(
                    tool=name,
                    kind="tool_added",
                    severity="LOW",
                    detail=f"New tool '{name}' not present in baseline; review for shadowing",
                )
            )

    for name in baseline:
        if name not in current:
            findings.append(
                DriftFinding(
                    tool=name,
                    kind="tool_removed",
                    severity="INFO",
                    detail=f"Tool '{name}' from baseline no longer advertised",
                )
            )

    return findings


def detect_tool_drift(client: McpClient, baseline_path: Path | None) -> list[DriftFinding]:
    """Run drift detection against an optional persisted baseline.

    No baseline path: only same-enumeration shadowing is checked. Path given
    but absent: capture the current descriptors as the baseline (first run).
    Path present: diff current descriptors against it.
    """
    tools = client.list_tools()
    if baseline_path is None:
        return _shadowing_findings(tools)
    if not baseline_path.exists():
        save_tool_baseline(baseline_path, build_tool_baseline(tools))
        findings = _shadowing_findings(tools)
        findings.append(
            DriftFinding(
                tool="*",
                kind="tool_baseline_captured",
                severity="INFO",
                detail=f"Captured descriptor baseline for {len(tools)} tools at {baseline_path}",
            )
        )
        return findings
    return diff_tool_descriptors(load_tool_baseline(baseline_path), tools)
