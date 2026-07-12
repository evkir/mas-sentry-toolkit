# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit a discovered A2A AgentCard for security-relevant configuration."""

from __future__ import annotations

from dataclasses import dataclass, field

from mas_sentry.core.injection_scan import scan_string

from .client import AgentCard

# AgentCard skill counts above this threshold are flagged for review.
LARGE_SKILL_THRESHOLD = 20

# Four-lens taxonomy for Agent Card Poisoning: injection directives embedded in
# card metadata that hijack an orchestrator's LLM-based task routing. Same
# directive class MAS-Sentry detects in MCP tool descriptors and agent traffic.
_POISONING_TAGS = ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"]
# Cleartext card endpoint enables card tampering / impersonation in transit.
_CLEARTEXT_TAGS = ["CWE-319", "STRIDE_Tampering"]

# Four-lens taxonomy for the structural card findings, so every A2A card
# finding - not only poisoning/transport - carries ASI/CWE/STRIDE for
# consistent SARIF ranking and cross-taxonomy filtering.
# Missing / anonymous auth -> anyone can act as a client (impersonation).
_MISSING_AUTH_TAGS = ["ASI03_Identity_Abuse", "CWE-306", "STRIDE_Spoofing"]
# Uncapped streaming -> long-lived streams abused for resource exhaustion.
_STREAMING_TAGS = ["ASI07_Resource_Exhaustion", "CWE-400", "STRIDE_Denial_Of_Service"]
# Unsigned push callbacks -> receiver cannot verify sender authenticity.
_PUSH_TAGS = ["ASI03_Identity_Abuse", "CWE-345", "STRIDE_Spoofing"]
# Excessive advertised skill surface -> least-privilege violation, broader
# abuse paths. Softest of the set; kept LOW and tagged honestly, not padded.
_SKILL_SURFACE_TAGS = ["ASI02_Tool_Misuse", "CWE-272", "STRIDE_Elevation_Of_Privilege"]
# Absent card signature -> client cannot verify origin or detect tampering.
_UNSIGNED_CARD_TAGS = ["ASI03_Identity_Abuse", "CWE-347", "STRIDE_Spoofing"]


@dataclass(frozen=True, slots=True)
class CardFinding:
    severity: str
    title: str
    detail: str
    tags: list[str] = field(default_factory=list)


def audit_agent_card(card: AgentCard) -> list[CardFinding]:
    out: list[CardFinding] = []

    out.extend(_check_no_auth(card))

    auth = card.authentication or {}
    caps = card.capabilities or {}
    if caps.get("streaming") and not caps.get("rateLimits"):
        out.append(
            CardFinding(
                severity="MEDIUM",
                title="Streaming enabled without rate limits in capabilities",
                detail=("Long-lived streams can be abused for resource exhaustion"),
                tags=_STREAMING_TAGS,
            )
        )

    if caps.get("pushNotifications") and not auth.get("webhookSigning"):
        out.append(
            CardFinding(
                severity="MEDIUM",
                title="Push notifications enabled without webhook signing",
                detail=("Outgoing callbacks can be spoofed if no signing scheme is published"),
                tags=_PUSH_TAGS,
            )
        )

    if len(card.skills) > LARGE_SKILL_THRESHOLD:
        out.append(
            CardFinding(
                severity="LOW",
                title=f"Agent advertises {len(card.skills)} skills",
                detail=("Large skill surface increases attack surface; review for unused skills"),
                tags=_SKILL_SURFACE_TAGS,
            )
        )

    out.extend(_check_signature_absence(card))
    out.extend(_scan_card_poisoning(card))
    out.extend(_check_insecure_transport(card))

    return out


def _check_signature_absence(card: AgentCard) -> list[CardFinding]:
    """Flag an AgentCard published without a JWS signature (A2A v1.0 AgentCardSignature).

    Signing is optional per spec ("MAY"), but v1.0 defines it as the mechanism
    that lets a client verify a card originates from the claimed provider and
    was not tampered with (RFC 7515 JWS over RFC 8785 canonicalized content).
    An unsigned card cannot be distinguished from a spoofed or on-path-modified
    one, so absence is itself a passive finding.
    """
    if not card.raw.get("signatures"):
        return [
            CardFinding(
                severity="MEDIUM",
                title="AgentCard is not signed",
                detail=(
                    "No signatures[] field present; a client has no way to verify this "
                    "card originates from the claimed provider or was not tampered with "
                    "in transit (A2A v1.0 AgentCardSignature, RFC 7515 JWS)"
                ),
                tags=list(_UNSIGNED_CARD_TAGS),
            )
        ]
    return []


def _check_no_auth(card: AgentCard) -> list[CardFinding]:
    """Flag an AgentCard that enforces no authentication requirement.

    Checks both card shapes MST may see in a mixed real-world fleet (same
    rationale as the discovery fallback in client.py): A2A v1.0's
    securitySchemes/security pair, and the legacy v0.3.x authentication.schemes
    list. A card is treated as v1.0-shaped if either v1.0 key is present in
    the raw payload; only then is the legacy check skipped, so a real v1.0
    card with auth configured is not double-flagged by a shape it no longer
    emits (v1.0 has no "authentication" field at all - see the discovery
    fallback docstring). If neither key is present the card is checked the
    legacy way, which still resolves correctly for a genuinely auth-less card.
    """
    if "securitySchemes" in card.raw or "security" in card.raw:
        if not card.raw.get("security"):
            return [
                CardFinding(
                    severity="HIGH",
                    title="AgentCard enforces no authentication requirement",
                    detail=(
                        "security[] is empty or absent, so no securitySchemes entry is "
                        "actually required to submit tasks - anyone can act as a client "
                        "(A2A v1.0 AgentCard.security)"
                    ),
                    tags=_MISSING_AUTH_TAGS,
                )
            ]
        return []

    auth = card.authentication or {}
    schemes = auth.get("schemes") or []
    if not schemes:
        return [
            CardFinding(
                severity="HIGH",
                title="AgentCard declares no authentication schemes",
                detail="Anyone can submit tasks to this agent",
                tags=_MISSING_AUTH_TAGS,
            )
        ]
    if "none" in [str(s).lower() for s in schemes]:
        return [
            CardFinding(
                severity="HIGH",
                title="AgentCard explicitly allows scheme 'none'",
                detail="Anonymous access enabled",
                tags=_MISSING_AUTH_TAGS,
            )
        ]
    return []


def _scan_card_poisoning(card: AgentCard) -> list[CardFinding]:
    """Detect injection directives embedded in LLM-ingested card metadata.

    An orchestrator selects specialist agents by reasoning over card
    descriptions; adversarial instructions in those fields hijack task routing
    (Agent Card Poisoning). We scan the card description and every skill's name
    and description with the shared injection primitive.
    """
    out: list[CardFinding] = []
    fields: list[tuple[str, str]] = [("description", card.description or "")]
    for i, skill in enumerate(card.skills):
        if not isinstance(skill, dict):
            continue
        sid = str(skill.get("id") or skill.get("name") or i)
        fields.append((f"skills[{sid}].name", str(skill.get("name", ""))))
        fields.append((f"skills[{sid}].description", str(skill.get("description", ""))))

    for location, text in fields:
        matches = scan_string(text)
        if not matches:
            continue
        patterns = sorted({m.pattern for m in matches})
        out.append(
            CardFinding(
                severity="HIGH",
                title=f"Agent Card Poisoning: injection directive in {location}",
                detail=(
                    f"Card metadata carries injection directive(s) [{', '.join(patterns)}] "
                    "that can hijack an orchestrator's task-routing reasoning"
                ),
                tags=list(_POISONING_TAGS),
            )
        )
    return out


def _check_insecure_transport(card: AgentCard) -> list[CardFinding]:
    """Flag a cleartext (http://) card endpoint - it invites card tampering."""
    url = (card.url or "").strip().lower()
    if url.startswith("http://"):
        return [
            CardFinding(
                severity="MEDIUM",
                title="AgentCard endpoint served over cleartext HTTP",
                detail=("Card and task traffic are unencrypted; an on-path attacker can tamper the card or messages"),
                tags=list(_CLEARTEXT_TAGS),
            )
        ]
    return []
