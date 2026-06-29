# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adapters: legacy module outputs -> unified Finding.

Each adapter takes one of the existing finding types from the codebase
(AgenticFinding, MCP scan JSON entries, A2A CardFinding) and produces the
unified core.Finding so downstream tooling (UnifiedThreatEngine, exporters,
reporting) can treat them uniformly.
"""

from __future__ import annotations

from typing import Any

from mas_sentry.agentic.base import AgenticFinding
from mas_sentry.protocols.a2a.card_audit import CardFinding

from .finding import Finding, Severity

# MITRE ATLAS technique IDs for agentic detectors with a clean, verified match.
_ASI_ATLAS = {
    "ASI01_Goal_Hijack": "AML.T0051",  # goal hijack via (indirect) prompt injection
    "ASI04_Memory_Poisoning": "AML.T0080",  # AI Agent Context Poisoning
    "ASI08_Supply_Chain": "AML.T0048",  # ML Supply Chain Compromise
}


def from_agentic(af: AgenticFinding) -> Finding:
    """Map an AgenticFinding (ASI01-ASI10) into the unified Finding."""
    asi_code = af.asi.value.split("_")[0].lower()  # "ASI01_Goal_Hijack" -> "asi01"
    tags = [af.asi.value]
    if af.cwe:
        tags.append(af.cwe)
    atlas = _ASI_ATLAS.get(af.asi.value)
    if atlas:
        tags.append(atlas)
    return Finding(
        module=f"agentic.{asi_code}",
        title=af.title,
        detail=af.detail,
        severity=_to_sev(af.severity),
        target=af.target,
        tags=tags,
        evidence=af.evidence,
        captured_at=af.captured_at,
    )


# Three-lens taxonomy (ASI/CWE/STRIDE) for the security-meaningful MCP checks.
# Drift checks reuse the same tag format the ABFP surface emits.
_MCP_CHECK_TAGS = {
    "tool_rug_pull": ["ASI08_Supply_Chain", "CWE-494", "STRIDE_Tampering", "AML.T0110"],
    "tool_shadowing": ["ASI02_Tool_Misuse", "CWE-290", "STRIDE_Spoofing", "AML.T0110"],
}


def from_mcp_check(check_dict: dict[str, Any], target: str) -> Finding:
    """Map one entry of a `mas-sentry mcp scan --out` JSON array.

    The JSON shape is {check, severity, detail}. We synthesize a human title
    from check + a slice of detail so the unified Finding is informative on
    its own (the raw `check` value alone is a category, not a title).
    """
    check_name = str(check_dict.get("check", "unknown"))
    detail = str(check_dict.get("detail", ""))
    title = f"{check_name}: {detail[:60]}" if detail else check_name
    evidence = {k: v for k, v in check_dict.items() if k not in {"check", "severity", "detail"}}
    return Finding(
        module=f"mcp.{check_name}",
        title=title,
        detail=detail,
        severity=_to_sev(check_dict.get("severity", "INFO")),
        target=target,
        tags=[check_name, *_MCP_CHECK_TAGS.get(check_name, [])],
        evidence=evidence,
    )


def from_card_audit(card_finding: CardFinding, target: str) -> Finding:
    """Map a CardFinding from A2A card audit into the unified Finding."""
    return Finding(
        module="a2a.card_audit",
        title=card_finding.title,
        detail=card_finding.detail,
        severity=_to_sev(card_finding.severity),
        target=target,
        tags=["a2a"],
    )


def _to_sev(s: str) -> Severity:
    try:
        return Severity(s.upper())
    except (ValueError, AttributeError):
        return Severity.INFO
