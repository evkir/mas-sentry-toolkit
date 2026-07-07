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
from mas_sentry.agents.abfp.injection_propagation import PropagationFinding
from mas_sentry.protocols.a2a.card_audit import CardFinding
from mas_sentry.protocols.a2a.probes import ProbeResult

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
    # Tool-poisoning carries IPI directives in the descriptor fields the LLM ingests.
    "tool_poisoning": ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"],
    # Argument injection into tool calls is classic command injection - no clean
    # ATLAS technique, so it is deliberately left ATLAS-untagged.
    "arg_injection": ["ASI02_Tool_Misuse", "CWE-77", "STRIDE_Tampering"],
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
        tags=["a2a", *card_finding.tags],
    )


# Per-probe taxonomy for A2A active probes. Tags attach only when the probe
# FAILS (unsafe server behavior actually observed); a probe that holds is
# recorded as INFO without a vulnerability class, so reports stay honest.
_PROBE_TAGS = {
    # Two tasks accepted under one id -> task-namespace identity confusion.
    "task-id-collision": ["ASI03_Identity_Abuse", "CWE-345", "STRIDE_Spoofing"],
    # Cancelling a task we never submitted -> missing authorization. No clean
    # agentic-top-10 slot, so ASI is deliberately omitted (like arg_injection
    # is left ATLAS-untagged).
    "unauthorized-cancel": ["CWE-862", "STRIDE_Elevation_Of_Privilege"],
    # Canary leaked into artifacts -> goal hijack via indirect prompt injection.
    "indirect-injection": ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"],
}

_PROBE_SEVERITY = {
    "task-id-collision": Severity.HIGH,
    "unauthorized-cancel": Severity.HIGH,
    "indirect-injection": Severity.CRITICAL,
}


def from_probe_result(probe: ProbeResult, target: str) -> Finding:
    """Map an A2A ProbeResult into the unified Finding.

    `probe.passed is True` means the server behaved safely; that is recorded
    as an INFO finding so the scan report shows every probe that ran, but it
    carries no vulnerability taxonomy because nothing was exploited. A failed
    probe is the real security finding and carries the mapped severity + tags.
    """
    base_tags = ["a2a", "probe", probe.name]
    if probe.passed:
        return Finding(
            module=f"a2a.probe.{probe.name}",
            title=f"{probe.name}: server behaved safely",
            detail=probe.detail,
            severity=Severity.INFO,
            target=target,
            tags=base_tags,
        )
    return Finding(
        module=f"a2a.probe.{probe.name}",
        title=f"{probe.name}: unsafe server behavior",
        detail=probe.detail,
        severity=_PROBE_SEVERITY.get(probe.name, Severity.MEDIUM),
        target=target,
        tags=[*base_tags, *_PROBE_TAGS.get(probe.name, [])],
    )


def from_propagation_finding(
    pf: PropagationFinding,
    target: str,
    blast_radius: dict[str, Any] | None = None,
) -> Finding:
    """Map a PropagationFinding (transitive injection contamination) into a Finding.

    ``pf.target`` is the contaminated agent; ``target`` is the scan target (the
    mesh or broker the agents run on). When the caller has the onward blast
    radius it is fused into evidence, so a report reader sees the contamination
    cone of each hop, not merely the fact that contamination happened.
    """
    evidence: dict[str, Any] = {
        "contaminated_agent": pf.target,
        "origin": pf.origin,
        "depth": pf.depth,
        "tier": pf.tier,
        "chain": list(pf.chain),
    }
    if blast_radius:
        evidence["blast_radius"] = blast_radius
    chain = " -> ".join(pf.chain)
    return Finding(
        module="abfp.propagation",
        title=f"Injection propagation to {pf.target} (depth {pf.depth}, {pf.tier})",
        detail=f"Contaminated via {pf.tier} relay across {pf.depth} hop(s) from {pf.origin}: {chain}",
        severity=_to_sev(pf.severity),
        target=target,
        tags=list(pf.tags),
        evidence=evidence,
    )


def _to_sev(s: str) -> Severity:
    try:
        return Severity(s.upper())
    except (ValueError, AttributeError):
        return Severity.INFO
