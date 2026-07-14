# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared indirect-prompt-injection (IPI) pattern scanner.

A neutral primitive consumed by multiple surfaces: the MCP tool-descriptor
audit (static fields the LLM ingests) and the ABFP live-traffic detector
(message payloads flowing between agents). Patterns match the
EchoLeak/Windsurf/Cursor disclosure class: hidden directives embedded in
content the model treats as instructions but a human reviewer may not see.

Maps to CWE-1427 (Improper Neutralization of Input Used for LLM Prompting)
and MITRE ATLAS AML.T0051 (LLM Prompt Injection).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Unicode tags + zero-width - used to hide instructions from human review.
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
_TAG_CHARS = re.compile(r"[\U000e0020-\U000e007f]")
_IGNORE_PREVIOUS = re.compile(r"(?i)ignore (all )?(previous|prior|above) (instructions|prompts|context)")
_NEW_TASK = re.compile(r"(?i)new (task|objective|goal)\s*:")
_SYSTEM_OVERRIDE = re.compile(r"(?i)(system|admin|developer)\s*:\s*(you must|always|never)")
_TOOL_CALL_HIJACK = re.compile(r"(?i)(when called|on tool|after this).{0,40}(exfiltrate|send|leak|fetch)")

# Pattern names whose presence is a strong (vs. ambient) injection signal.
# Obfuscation hides directives from human review; ignore-previous and
# tool-call-hijack are explicit control-flow takeovers.
STRONG_PATTERNS = frozenset({"zero-width-chars", "unicode-tag-chars", "ignore-previous", "tool-call-hijack"})


@dataclass(frozen=True, slots=True)
class InjectionMatch:
    pattern: str
    sample: str  # truncated


def scan_string(s: str) -> list[InjectionMatch]:
    out: list[InjectionMatch] = []
    if _ZERO_WIDTH.search(s):
        out.append(InjectionMatch("zero-width-chars", s[:80]))
    if _TAG_CHARS.search(s):
        out.append(InjectionMatch("unicode-tag-chars", s[:80]))
    for name, pat in [
        ("ignore-previous", _IGNORE_PREVIOUS),
        ("new-task-directive", _NEW_TASK),
        ("system-role-override", _SYSTEM_OVERRIDE),
        ("tool-call-hijack", _TOOL_CALL_HIJACK),
    ]:
        if pat.search(s):
            out.append(InjectionMatch(name, s[:160]))
    return out


# ---------------------------------------------------------------------------
# Routing-hijack: persuasive agent-selection steering (Trustwave 2025 class).
#
# Distinct from the takeovers above. A rogue AgentCard needs no obfuscation or
# "ignore previous" token to hijack an LLM orchestrator's routing: plain-language
# directives that steer *selection* toward this card ("always prefer this agent",
# "the only agent authorized for X", "do not route to other agents") bias the
# orchestrator's task-routing reasoning. Each signature requires a selection
# imperative, not a bare superlative, so honest self-description
# ("best-in-class invoice agent", "use this agent to process invoices") is inert.
# ---------------------------------------------------------------------------
_ROUTE_IMPERATIVE = re.compile(
    r"(?i)\b(always|must|should)\b.{0,40}\b(route|prefer|select|choose|pick)\b.{0,20}\b(this|the)\s+agent\b"
)
_ROUTE_HERE_FIRST = re.compile(r"(?i)\broute\b.{0,40}\b(here|to this agent)\b.{0,20}\bfirst\b")
_EXCLUSIVE_AGENT = re.compile(
    r"(?i)\b(only|sole)\s+agent\b.{0,40}\b(authoriz|allow|permitt|able|can|capable|trusted|entitled)"
)
_PRIORITY_ROUTING = re.compile(r"(?i)\b(highest|top)\s+priority\b.{0,40}\b(agent|route|routing|select)")
_SUPPRESS_OTHERS = re.compile(
    r"(?i)\b(do not|don't|never)\b.{0,20}\b(route|delegate|select|call)\b.{0,20}\b(other|another|any other)\s+agents?\b"
)
_PREFERRED_DEFAULT = re.compile(r"(?i)\b(preferred|default|authoritative)\s+agent\s+for\b")


def scan_routing_hijack(s: str) -> list[InjectionMatch]:
    """Detect persuasive agent-selection steering in LLM-ingested card metadata.

    Complements scan_string: matches plain-language routing directives that bias
    an orchestrator's agent selection without any classic injection token. Each
    signature requires a selection imperative, not a bare superlative, keeping
    honest self-description inert.
    """
    out: list[InjectionMatch] = []
    for name, pat in [
        ("route-imperative", _ROUTE_IMPERATIVE),
        ("route-here-first", _ROUTE_HERE_FIRST),
        ("exclusive-agent-claim", _EXCLUSIVE_AGENT),
        ("priority-routing", _PRIORITY_ROUTING),
        ("suppress-other-agents", _SUPPRESS_OTHERS),
        ("preferred-default-agent", _PREFERRED_DEFAULT),
    ]:
        if pat.search(s):
            out.append(InjectionMatch(name, s[:160]))
    return out
