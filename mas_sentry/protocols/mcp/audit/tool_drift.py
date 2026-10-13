# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP tool-descriptor drift detection (rug-pull / shadowing).

Captures a baseline of each tool's descriptor (description plus input schema)
keyed by tool name, then on a later scan flags:

- tool_rug_pull: an existing tool whose descriptor mutated after the baseline
  was captured -- the classic post-approval rug pull that most MCP clients do
  not detect;
- tool_shadowing: two or more tools advertising the same name within a single
  enumeration;
- tool_added / tool_removed: tools appearing or disappearing relative to the
  baseline.

The baseline keeps the descriptor itself rather than a digest of it, and that
is the point of the format. A digest proves that something moved; it cannot say
what it moved from, so a row built on one can never carry both sides of the
change a reviewer needs in order to rebuild the verdict (R-7.2). It also cannot
say what a withdrawn tool's input schema was, which is the one input that lets
a probe ask a server about a tool it has stopped advertising without guessing
either the name or the arguments.

Two shapes are therefore read. A string value is a digest written by an earlier
release: the change is still detected, and the row says the prior side was
never recorded instead of implying it was clean (R-2.1). An object value
carries the descriptor. Baselines are committed next to a project and live in
CI, so dropping the older shape would have silently stopped detecting rug pulls
on every one of them.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..client import McpClient, ToolDef


@dataclass(frozen=True, slots=True)
class DriftFinding:
    tool: str
    kind: str  # tool_rug_pull / tool_shadowing / tool_added / tool_removed / tool_baseline_captured
    severity: str
    detail: str


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """One tool as a baseline recorded it.

    The digest is always present, because it is what the comparison runs on in
    either shape. `description` is None only for the digest-only shape, which
    is how an entry reports that the prior side of a change is unavailable
    rather than empty.
    """

    digest: str
    description: str | None = None
    input_schema: dict[str, Any] | None = None

    @property
    def has_descriptor(self) -> bool:
        """Whether the prior side of a change can be read off this entry."""
        return self.description is not None


def _digest(description: str, input_schema: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"description": description, "input_schema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()


def tool_descriptor_digest(tool: ToolDef) -> str:
    """Stable SHA-256 over a tool's security-relevant descriptor surface."""
    return _digest(tool.description, tool.input_schema)


def build_tool_baseline(tools: list[ToolDef]) -> dict[str, BaselineEntry]:
    """Record each tool's descriptor, keyed by name (last write wins on duplicates)."""
    return {
        t.name: BaselineEntry(
            digest=tool_descriptor_digest(t),
            description=t.description,
            input_schema=t.input_schema,
        )
        for t in tools
    }


def save_tool_baseline(path: Path, baseline: dict[str, BaselineEntry]) -> None:
    """Write the baseline, keeping the shape each entry actually has.

    An entry loaded from a digest-only file is written back as a digest.
    Filling in a descriptor it never carried would make the next run report a
    prior side that nothing ever observed.
    """
    payload: dict[str, Any] = {
        name: (
            {"description": entry.description, "input_schema": entry.input_schema}
            if entry.has_descriptor
            else entry.digest
        )
        for name, entry in baseline.items()
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def _entry_from(name: str, value: Any) -> BaselineEntry:
    """One record, in whichever of the two shapes it was written."""
    if isinstance(value, str):
        return BaselineEntry(digest=value)
    if isinstance(value, dict):
        description = value.get("description")
        schema = value.get("input_schema")
        if isinstance(description, str) and isinstance(schema, dict):
            return BaselineEntry(
                digest=_digest(description, schema),
                description=description,
                input_schema=schema,
            )
    raise ValueError(f"baseline entry for '{name}' is neither a digest nor a descriptor")


def load_tool_baseline(path: Path) -> dict[str, BaselineEntry]:
    """Load a baseline in either shape; empty dict if the file is absent.

    A record in neither shape is refused rather than skipped. A baseline read
    in part would compare the live inventory against fewer tools than the file
    lists and report the remainder as unchanged.
    """
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {str(name): _entry_from(str(name), value) for name, value in data.items()}


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
