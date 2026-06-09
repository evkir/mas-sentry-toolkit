# SPDX-License-Identifier: AGPL-3.0-or-later
"""Single Finding model used by every module. Replaces ad-hoc dicts.

Note: legacy FindingDict (mas_sentry.core.types) and the protocol-specific
finding dataclasses (ProtocolFinding, AgenticFinding, CardFinding, RogueFinding)
remain for now. The unified Finding here is the target for new code and
incremental migration via adapters (core/adapters.py).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEV_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """Unified Finding emitted by every module.

    Examples of `module`: "mcp.audit.ssrf", "agentic.asi01_goal_hijack",
    "a2a.card_audit", "mqtt.broker_anon".

    `tags` carries cross-cutting taxonomy markers like "ASI01", "STRIDE:T",
    "OWASP-LLM01", "CWE-94". `references` is for URLs to advisories.
    """

    module: str
    title: str
    detail: str
    severity: Severity
    target: str
    tags: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    captured_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def rank(sev: Severity) -> int:
    return _SEV_RANK[sev]


def max_severity(findings: list[Finding]) -> Severity:
    """Highest severity in the list. Empty list → INFO."""
    if not findings:
        return Severity.INFO
    return max((f.severity for f in findings), key=rank)
