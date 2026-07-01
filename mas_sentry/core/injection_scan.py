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
