# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit a discovered A2A AgentCard for security-relevant configuration."""

from __future__ import annotations

from dataclasses import dataclass

from .client import AgentCard

# AgentCard skill counts above this threshold are flagged for review.
LARGE_SKILL_THRESHOLD = 20


@dataclass(frozen=True, slots=True)
class CardFinding:
    severity: str
    title: str
    detail: str


def audit_agent_card(card: AgentCard) -> list[CardFinding]:
    out: list[CardFinding] = []

    auth = card.authentication or {}
    schemes = auth.get("schemes") or []
    if not schemes:
        out.append(
            CardFinding(
                severity="HIGH",
                title="AgentCard declares no authentication schemes",
                detail="Anyone can submit tasks to this agent",
            )
        )
    elif "none" in [str(s).lower() for s in schemes]:
        out.append(
            CardFinding(
                severity="HIGH",
                title="AgentCard explicitly allows scheme 'none'",
                detail="Anonymous access enabled",
            )
        )

    caps = card.capabilities or {}
    if caps.get("streaming") and not caps.get("rateLimits"):
        out.append(
            CardFinding(
                severity="MEDIUM",
                title="Streaming enabled without rate limits in capabilities",
                detail=("Long-lived streams can be abused for resource exhaustion"),
            )
        )

    if caps.get("pushNotifications") and not auth.get("webhookSigning"):
        out.append(
            CardFinding(
                severity="MEDIUM",
                title="Push notifications enabled without webhook signing",
                detail=("Outgoing callbacks can be spoofed if no signing scheme is published"),
            )
        )

    if len(card.skills) > LARGE_SKILL_THRESHOLD:
        out.append(
            CardFinding(
                severity="LOW",
                title=f"Agent advertises {len(card.skills)} skills",
                detail=("Large skill surface increases attack surface; review for unused skills"),
            )
        )

    return out
