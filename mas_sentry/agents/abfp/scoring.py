# SPDX-License-Identifier: AGPL-3.0-or-later
"""Composite anomaly scoring across timing / payload / topic / identity dimensions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


WEIGHTS = {
    "timing": 0.25,
    "payload": 0.20,
    "topic": 0.35,
    "identity": 0.20,
    "burst": 0.15,
    # IPI directives observed in an agent's published traffic. Weighted high
    # enough that a strong single hit reaches MEDIUM on its own and escalates
    # to HIGH/CRITICAL when combined with topic/identity drift.
    "injection": 0.60,
}


@dataclass(frozen=True, slots=True)
class DimensionScore:
    name: str
    raw: float  # 0..1
    reason: str = ""


@dataclass(frozen=True, slots=True)
class AnomalyScore:
    agent_id: str
    total: int  # 0..100
    severity: Severity
    dimensions: list[DimensionScore] = field(default_factory=list)


def compose(agent_id: str, scores: list[DimensionScore]) -> AnomalyScore:
    weighted = 0.0
    total_w = 0.0
    for s in scores:
        w = WEIGHTS.get(s.name, 0.0)
        weighted += max(0.0, min(1.0, s.raw)) * w
        total_w += w
    norm = weighted / total_w if total_w else 0.0
    total = round(norm * 100)
    return AnomalyScore(
        agent_id=agent_id,
        total=total,
        severity=_severity_for(total),
        dimensions=scores,
    )


def _severity_for(total: int) -> Severity:
    if total >= 85:
        return Severity.CRITICAL
    if total >= 70:
        return Severity.HIGH
    if total >= 50:
        return Severity.MEDIUM
    if total >= 25:
        return Severity.LOW
    return Severity.INFO
