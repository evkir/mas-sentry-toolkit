# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASI03 — Identity & Privilege Abuse.

Validates:
- JWT/OAuth claims look like an agent (not a human bearer).
- Delegation chain length (RFC 8693 `act` claim depth).
- Token-replay window — if `nbf`/`exp` window > 1h on an agent token.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from .base import AgenticFinding, AsiCategory


@dataclass(frozen=True, slots=True)
class TokenInsight:
    claims: dict[str, Any]
    delegation_depth: int
    lifetime_seconds: int


def parse_jwt(token: str) -> TokenInsight | None:
    """Unsafe JWT decode — for audit only, signature is not verified.

    Returns None if the token cannot be parsed. Non-numeric `iat`/`exp`
    are tolerated and yield lifetime_seconds=0.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        payload = json.loads(_b64url(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    depth = _chain_depth(payload.get("act"))
    try:
        iat = int(payload.get("iat") or payload.get("nbf") or 0)
        exp = int(payload.get("exp") or 0)
        lifetime = max(0, exp - iat) if iat and exp else 0
    except (TypeError, ValueError):
        lifetime = 0
    return TokenInsight(claims=payload, delegation_depth=depth, lifetime_seconds=lifetime)


def audit_token(token: str, target: str) -> list[AgenticFinding]:
    insight = parse_jwt(token)
    if not insight:
        return []
    findings: list[AgenticFinding] = []

    # Delegation chain too long → privilege diffusion
    if insight.delegation_depth >= 3:
        findings.append(
            AgenticFinding(
                asi=AsiCategory.IDENTITY_ABUSE,
                severity="MEDIUM",
                title=f"Delegation chain depth = {insight.delegation_depth}",
                detail=("Long delegation chains weaken audit and increase impersonation surface"),
                target=target,
                evidence={"depth": insight.delegation_depth},
                cwe="CWE-269",
            )
        )

    # Agent token with long lifetime → replay window
    if insight.lifetime_seconds > 3600 and _looks_like_agent(insight.claims):
        findings.append(
            AgenticFinding(
                asi=AsiCategory.IDENTITY_ABUSE,
                severity="HIGH",
                title=f"Agent token lifetime = {insight.lifetime_seconds}s (> 1h)",
                detail=("Long-lived agent tokens enable replay if compromised; prefer short TTL + rotation"),
                target=target,
                evidence={
                    "lifetime_seconds": insight.lifetime_seconds,
                    "subject": insight.claims.get("sub"),
                },
                cwe="CWE-613",
            )
        )

    # Agent token with human-style claims (e.g. `email_verified`)
    if insight.claims.get("email_verified") is not None and _looks_like_agent(insight.claims):
        findings.append(
            AgenticFinding(
                asi=AsiCategory.IDENTITY_ABUSE,
                severity="MEDIUM",
                title="Agent token carries human-identity claims",
                detail=("Token mixes machine and human claim sets — audit attribution will be ambiguous"),
                target=target,
                evidence={"suspicious_claims": ["email_verified"]},
            )
        )

    return findings


def _b64url(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _chain_depth(act: Any, depth: int = 0) -> int:
    if not isinstance(act, dict):
        return depth
    return _chain_depth(act.get("act"), depth + 1)


def _looks_like_agent(claims: dict[str, Any]) -> bool:
    sub = str(claims.get("sub", "")).lower()
    aud = str(claims.get("aud", "")).lower()
    return any(t in sub + aud for t in ("agent", "service", "bot", "system", "mcp"))
