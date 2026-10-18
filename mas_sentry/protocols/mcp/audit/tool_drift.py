# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP tool-descriptor drift between runs (rug-pull / shadowing).

Compares a scan against a descriptor baseline committed next to a project and
flags:

- tool_rug_pull: an existing tool whose descriptor mutated after the baseline
  was captured -- the classic post-approval rug pull that most MCP clients do
  not detect;
- tool_shadowing: two or more tools advertising the same name within a single
  enumeration;
- tool_added / tool_removed: tools appearing or disappearing relative to the
  baseline.

This module decides only what is worth reporting. How a descriptor is recorded
and how it reaches a row as evidence belong to `descriptor`, which the
in-session half of this class (`tool_mutation`) and the authorization probe
read as well. The split happened when the second of those three appeared: one
judge supplying another judge's evidence format is the coupling R-1.7 exists
to prevent.

The span is what separates the two halves. Drift sees a swap that crosses
runs, so its prior side comes off disk and may predate the format that keeps
descriptors at all; mutation sees a swap inside one scan, where both sides
were observed by the same process.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from ..client import McpClient, ToolDef
from .descriptor import (
    Baseline,
    BaselineEntry,
    arrival_evidence,
    build_tool_baseline,
    change_evidence,
    departure_evidence,
    load_baseline,
    save_baseline,
)


@dataclass(frozen=True, slots=True)
class DriftFinding:
    tool: str
    kind: str  # tool_rug_pull / tool_shadowing / tool_added / tool_removed / tool_baseline_captured
    severity: str
    detail: str
    # Both sides of whatever the row claims, so a reviewer rebuilds the verdict
    # from the row instead of taking it on trust (R-7.2). Empty for a row whose
    # entire content is its sentence, such as same-enumeration shadowing.
    evidence: dict[str, str] = field(default_factory=dict)


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


def diff_tool_descriptors(baseline: dict[str, BaselineEntry], tools: list[ToolDef]) -> list[DriftFinding]:
    """Compare current tools against a prior baseline."""
    findings = _shadowing_findings(tools)
    current = build_tool_baseline(tools)

    for name, entry in current.items():
        prior = baseline.get(name)
        if prior is not None and prior.digest != entry.digest:
            findings.append(
                DriftFinding(
                    tool=name,
                    kind="tool_rug_pull",
                    severity="HIGH",
                    detail=f"Descriptor for '{name}' changed since baseline (post-approval mutation)",
                    evidence=change_evidence(prior, entry),
                )
            )
        elif prior is None:
            findings.append(
                DriftFinding(
                    tool=name,
                    kind="tool_added",
                    severity="LOW",
                    detail=f"New tool '{name}' not present in baseline; review for shadowing",
                    evidence=arrival_evidence(entry),
                )
            )

    for name, prior in baseline.items():
        if name not in current:
            findings.append(
                DriftFinding(
                    tool=name,
                    kind="tool_removed",
                    severity="INFO",
                    detail=f"Tool '{name}' from baseline no longer advertised",
                    evidence=departure_evidence(prior),
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
        save_baseline(baseline_path, Baseline(tools=build_tool_baseline(tools)))
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
    return diff_tool_descriptors(load_baseline(baseline_path).tools, tools)
