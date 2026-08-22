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
from mas_sentry.agents.abfp.coordination import CoordinationSignal
from mas_sentry.agents.abfp.injection_propagation import PropagationFinding
from mas_sentry.protocols.a2a.card_audit import CardFinding
from mas_sentry.protocols.a2a.probes import ProbeResult

from .finding import Finding, Severity

# MITRE ATLAS technique IDs for agentic detectors with a clean, verified match.
_ASI_ATLAS = {
    "ASI01_Goal_Hijack": "AML.T0051",  # goal hijack via (indirect) prompt injection
    "ASI06_Memory_Poisoning": "AML.T0080",  # AI Agent Context Poisoning
    "ASI04_Supply_Chain": "AML.T0048",  # ML Supply Chain Compromise
}


def from_agentic(af: AgenticFinding) -> Finding:
    """Map an AgenticFinding into the unified Finding.

    The module id comes from the enum member name, not from the tag value.
    Splitting the value on its prefix used to yield "asi08" for supply
    chain, which silently became a different category's number when the
    published list renumbered; it would now also collapse both MST_-prefixed
    categories onto one id.
    """
    asi_code = af.asi.name.lower()  # SUPPLY_CHAIN -> "supply_chain"
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
    "tool_rug_pull": ["ASI04_Supply_Chain", "CWE-494", "STRIDE_Tampering", "AML.T0110"],
    "tool_shadowing": ["ASI02_Tool_Misuse", "CWE-290", "STRIDE_Spoofing", "AML.T0110"],
    # Same class as tool_rug_pull, caught inside one session instead of across
    # runs: the descriptor moved after the inventory was read.
    "tool_mutation": ["ASI04_Supply_Chain", "CWE-494", "STRIDE_Tampering", "AML.T0110"],
    "tool_appeared": ["ASI04_Supply_Chain", "CWE-494", "STRIDE_Tampering", "AML.T0110"],
    # Tool-poisoning carries IPI directives in the descriptor fields the LLM ingests.
    "tool_poisoning": ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"],
    # Argument injection into tool calls is classic command injection - no clean
    # ATLAS technique, so it is deliberately left ATLAS-untagged.
    "arg_injection": ["ASI02_Tool_Misuse", "CWE-77", "STRIDE_Tampering"],
    # A tool that will fetch an attacker-chosen URL is server-side request
    # forgery reached through the tool surface, so the weakness is the fetch,
    # not whatever the operator happens to expose on the inside.
    "ssrf": ["ASI02_Tool_Misuse", "CWE-918", "STRIDE_Information_Disclosure"],
    "path_traversal": ["ASI02_Tool_Misuse", "CWE-22", "STRIDE_Information_Disclosure"],
    # Resource bodies and templated resource descriptors are ingested by the
    # model exactly like tool descriptors are, so a directive planted in one is
    # the same prompt-injection class as tool_poisoning and carries the same
    # four lenses.
    "resource_content": ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"],
    "resource_template": ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"],
    # The server accepted a request whose routing headers disagreed with its
    # body. One parser reading two meanings out of one message is an
    # interpretation conflict (CWE-436), not request smuggling (CWE-444),
    # which needs two parsers disagreeing along a proxy chain.
    "header_body_desync": ["ASI02_Tool_Misuse", "CWE-436", "STRIDE_Spoofing"],
    # An endpoint honouring a Host or Origin it should have refused is an
    # origin validation failure, whatever the attacker then reaches through it.
    "dns_rebind": ["ASI02_Tool_Misuse", "CWE-346", "STRIDE_Spoofing"],
    # A known-vulnerable server implementation is inherited risk, so it maps to
    # the supply-chain lens rather than to anything the operator wrote.
    "known_cve": ["ASI04_Supply_Chain", "CWE-1395"],
    # User-controlled data reaching the stdio command line is OS command
    # injection, and the agentic consequence is code the operator never
    # authorised running on the server host.
    "stdio_rce": ["ASI05_Unexpected_Code_Execution", "CWE-78", "STRIDE_Elevation_Of_Privilege"],
    # A consent address the person is asked to trust with no way to check it:
    # cleartext, a bare IP, or credentials packed ahead of the host. Origin
    # validation is the weakness class; the human is who it is spent on.
    "elicitation_url": ["ASI09_Human_Agent_Trust", "CWE-346", "STRIDE_Spoofing"],
    # An MCP Apps document declares which origins its iframe may reach. A
    # wildcard or a cleartext origin in that declaration is a permissive
    # cross-domain policy on a page the audited server wrote.
    "app_ui_reach": ["ASI09_Human_Agent_Trust", "CWE-942", "STRIDE_Spoofing"],
    # Browser capabilities the same document asks the host to grant it.
    "app_permissions": ["ASI09_Human_Agent_Trust", "CWE-272", "STRIDE_Elevation_Of_Privilege"],
    # Where the document actually reaches, against where it said it would.
    "app_html_reach": ["ASI09_Human_Agent_Trust", "CWE-942", "STRIDE_Information_Disclosure"],
    # The app-to-host channel addressed to whatever embeds the iframe.
    "app_html_channel": ["ASI09_Human_Agent_Trust", "CWE-346", "STRIDE_Spoofing"],
    # Form mode is specified for non-sensitive input, so a schema collecting a
    # secret routes a credential through the client and into model context.
    "elicitation_secret_field": ["ASI09_Human_Agent_Trust", "CWE-522", "STRIDE_Information_Disclosure"],
}
# Deliberately absent from the table: fingerprint, enumeration_gap,
# input_required, capability_required, app_surface and app_binding. None of
# them asserts a weakness - they report what the scan
# saw and what it could not reach - so hanging a CWE on them would put
# coverage notes into the same SARIF filters an operator uses to triage real
# findings. Their bare check name is the whole tag list on purpose.


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

    A probe that could not complete carries no verdict at all and is recorded
    as an INFO finding saying so - dropping it would leave the report looking
    like the check ran and found nothing.

    `probe.passed is True` means the server behaved safely; that is recorded
    as an INFO finding so the scan report shows every probe that ran, but it
    carries no vulnerability taxonomy because nothing was exploited. A failed
    probe is the real security finding and carries the mapped severity + tags.
    """
    base_tags = ["a2a", "probe", probe.name]
    if not probe.conclusive:
        return Finding(
            module=f"a2a.probe.{probe.name}",
            title=f"{probe.name}: probe could not run",
            detail=probe.detail,
            severity=Severity.INFO,
            target=target,
            tags=base_tags,
        )
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


# A coupling this strong is worth putting in front of a reader first; below it
# the pair is still reported, but as a lead rather than a highlighted one.
_COORDINATION_STRONG_Z = 12.0


def from_coordination_signal(signal: CoordinationSignal, target: str) -> Finding:
    """Map a coordination side-channel signal into a Finding.

    Severity is deliberately capped low. The detector measures that two agents
    are locked in time with no topic path to explain it - that is a lead for a
    human to investigate, not proof of malice, and a benign cause (an unobserved
    broker, a shared external trigger) can produce the same shape. The z score,
    the observed coupling and the surrogate null all ship in evidence so the
    reader can judge the effect instead of trusting the label.
    """
    severity = Severity.MEDIUM if signal.z >= _COORDINATION_STRONG_Z else Severity.LOW
    return Finding(
        module="abfp.coordination",
        title=f"Unexplained temporal coupling: {signal.source} -> {signal.target} (z={signal.z})",
        detail=(
            f"{signal.target} publishes within the response window of {signal.source} far more often "
            f"than a phase-randomised surrogate of its own traffic would ({signal.observed} observed vs "
            f"{signal.null_mean} expected, {signal.z} sigma over {signal.events} source events), and no "
            "publish/consume path in the observed topic graph accounts for it. The pair is coordinating "
            "over a channel this scan cannot see - investigate the link before treating it as benign"
        ),
        severity=severity,
        target=target,
        tags=["abfp", "coordination", "ASI07_Insecure_Communication", "CWE-514", "STRIDE_Information_Disclosure"],
        evidence={
            "source": signal.source,
            "target_agent": signal.target,
            "z": signal.z,
            "observed": signal.observed,
            "null_mean": signal.null_mean,
            "source_events": signal.events,
        },
    )
