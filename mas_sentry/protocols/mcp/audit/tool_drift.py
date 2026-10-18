# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP inventory drift between runs (rug-pull / shadowing / revision).

Compares a scan against a baseline committed next to a project and flags:

- tool_rug_pull: an existing tool whose descriptor mutated after the baseline
  was captured -- the classic post-approval rug pull that most MCP clients do
  not detect;
- tool_shadowing: two or more tools advertising the same name within a single
  enumeration;
- tool_added / tool_removed: tools appearing or disappearing relative to the
  baseline;
- protocol_revision_changed: the revision the target announces is not the one
  the baseline recorded. A downgrade is the direction that matters, because an
  older revision requires less of the server and what it stopped requiring is
  not knowable from the handshake alone.

The revision is read off `client.server`, which carries what the target
announced, and never off `client.protocol_version`, which is this client's own
negotiated state. Measured against a rig announcing two different revisions:
`client.server.protocol_version` followed the target both times while
`client.protocol_version` stayed at the legacy fallback. A judge on the latter
would compare the scanner against itself and never report anything, and in the
other direction would publish a bound of the scanner as a fact about the
target (R-2.5).

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

import re
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
    kind: str  # tool_rug_pull / tool_shadowing / tool_added / tool_removed /
    # tool_baseline_captured / protocol_revision_changed / protocol_revision_unverified
    severity: str
    detail: str
    # Both sides of whatever the row claims, so a reviewer rebuilds the verdict
    # from the row instead of taking it on trust (R-7.2). Empty for a row whose
    # entire content is its sentence, such as same-enumeration shadowing.
    evidence: dict[str, str] = field(default_factory=dict)


# MCP revisions are dates, and the client already picks the newest by comparing
# them as strings (`max(offered)` in `client._try_discover`). The same ordering
# is what makes "older" mean anything here. A revision that is not date-shaped
# is a server saying something this comparison cannot rank, so the direction is
# reported as unreadable rather than guessed.
_DATED_REVISION = re.compile(r"\d{4}-\d{2}-\d{2}")


def _revision_findings(prior: str | None, current: str | None) -> list[DriftFinding]:
    """What the two sides of the announced revision say, or why they say nothing.

    Three outcomes, and the two that are not a change keep their own key so a
    run that could not compare is never read as a run that found nothing
    (R-7.5). Severity is spent on the downgrade: an older revision requires
    less of the server, and an upgrade requires more, which is not a weakness.
    """
    if prior is None and not current:
        # Neither side observed a revision, so there is no gap to report. A row
        # here would fire on every run against any target that announces none,
        # and would say only that nothing was ever asked.
        return []
    if prior is None:
        return [
            DriftFinding(
                tool="*",
                kind="protocol_revision_unverified",
                severity="INFO",
                detail=(
                    "The baseline records no protocol revision, so this run cannot say whether the "
                    "target changed the revision it announces. Recapture the baseline to compare."
                ),
                evidence={"reason": "baseline-predates-field", "current_revision": current or ""},
            )
        ]
    if not current:
        return [
            DriftFinding(
                tool="*",
                kind="protocol_revision_unverified",
                severity="INFO",
                detail=(
                    "The target announced no protocol revision on this run, so the revision the "
                    "baseline recorded has nothing to be compared against."
                ),
                evidence={"reason": "target-announced-none", "previous_revision": prior},
            )
        ]
    if current == prior:
        return []
    dated = bool(_DATED_REVISION.fullmatch(prior)) and bool(_DATED_REVISION.fullmatch(current))
    direction = "upgrade" if dated and current > prior else "downgrade" if dated else "unreadable"
    return [
        DriftFinding(
            tool="*",
            kind="protocol_revision_changed",
            severity="INFO" if direction == "upgrade" else "MEDIUM",
            detail=(
                f"The target announces protocol revision {current}, and the baseline recorded "
                f"{prior}. Read as a {direction}."
            ),
            evidence={"previous_revision": prior, "current_revision": current, "direction": direction},
        )
    ]


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


def _announced_revision(client: McpClient) -> str | None:
    """The revision the target announced, or None if no handshake result exists.

    `client.server` and not `client.protocol_version`: the first is what the
    target said, the second is this client's own negotiated state and stays at
    the legacy fallback whatever the target announces.
    """
    return client.server.protocol_version if client.server is not None else None


def detect_inventory_drift(client: McpClient, baseline_path: Path | None) -> list[DriftFinding]:
    """Run drift detection against an optional persisted baseline.

    No baseline path: only same-enumeration shadowing is checked, because that
    is the one class observable without a prior side. Path given but absent:
    capture the inventory as the baseline (first run). Path present: diff the
    current inventory against it.
    """
    tools = client.list_tools()
    if baseline_path is None:
        return _shadowing_findings(tools)
    if not baseline_path.exists():
        save_baseline(
            baseline_path,
            Baseline(tools=build_tool_baseline(tools), protocol_revision=_announced_revision(client)),
        )
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
    baseline = load_baseline(baseline_path)
    return diff_tool_descriptors(baseline.tools, tools) + _revision_findings(
        baseline.protocol_revision, _announced_revision(client)
    )
