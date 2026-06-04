# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASI06 — Untraceable Actions.

Checks a sample of tool-call records and reports missing-trace coverage.
A "record" is a dict with at least: tool, timestamp, optional
traceparent / span_id and user_id / actor.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .base import AgenticFinding, AsiCategory

# Coverage thresholds (fraction of records with the relevant field).
TRACE_COVERAGE_MIN = 0.9
TRACE_COVERAGE_HIGH_SEV_BELOW = 0.5
ATTRIB_COVERAGE_MIN = 0.9


@dataclass(frozen=True, slots=True)
class CoverageStats:
    total: int
    with_trace: int
    with_user_attribution: int


def audit_action_log(records: list[dict[str, Any]], target: str) -> list[AgenticFinding]:
    if not records:
        return []
    stats = CoverageStats(
        total=len(records),
        with_trace=sum(1 for r in records if r.get("traceparent") or r.get("span_id")),
        with_user_attribution=sum(1 for r in records if r.get("user_id") or r.get("actor")),
    )
    findings: list[AgenticFinding] = []

    trace_ratio = stats.with_trace / stats.total
    if trace_ratio < TRACE_COVERAGE_MIN:
        severity = "HIGH" if trace_ratio < TRACE_COVERAGE_HIGH_SEV_BELOW else "MEDIUM"
        findings.append(
            AgenticFinding(
                asi=AsiCategory.ASI06,
                severity=severity,
                title=f"Trace coverage = {trace_ratio:.0%}",
                detail=(f"{stats.total - stats.with_trace} of {stats.total} tool calls have no trace ID"),
                target=target,
                evidence={"trace_ratio": trace_ratio, "total": stats.total},
                cwe="CWE-778",
            )
        )

    attrib_ratio = stats.with_user_attribution / stats.total
    if attrib_ratio < ATTRIB_COVERAGE_MIN:
        findings.append(
            AgenticFinding(
                asi=AsiCategory.ASI06,
                severity="HIGH",
                title=f"User attribution coverage = {attrib_ratio:.0%}",
                detail=(f"{stats.total - stats.with_user_attribution} actions lack actor/user attribution"),
                target=target,
                evidence={"attrib_ratio": attrib_ratio, "total": stats.total},
                cwe="CWE-282",
            )
        )

    return findings
