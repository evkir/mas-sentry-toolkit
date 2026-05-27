# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detect indirect-prompt-injection patterns in tool descriptions and results.

These match the EchoLeak/Windsurf/Cursor disclosure pattern: hidden directives
embedded in fields the LLM ingests but the user does not see.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Unicode tags + zero-width — used to hide instructions from human review.
_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
_TAG_CHARS = re.compile(r"[\U000e0020-\U000e007f]")
_IGNORE_PREVIOUS = re.compile(r"(?i)ignore (all )?(previous|prior|above) (instructions|prompts|context)")
_NEW_TASK = re.compile(r"(?i)new (task|objective|goal)\s*:")
_SYSTEM_OVERRIDE = re.compile(r"(?i)(system|admin|developer)\s*:\s*(you must|always|never)")
_TOOL_CALL_HIJACK = re.compile(r"(?i)(when called|on tool|after this).{0,40}(exfiltrate|send|leak|fetch)")


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


def scan_tool_definitions(
    tools: list[dict[str, Any]],
) -> dict[str, list[InjectionMatch]]:
    findings: dict[str, list[InjectionMatch]] = {}
    for t in tools:
        name = t.get("name", "<anonymous>")
        candidates = [t.get("description", "")]
        schema = t.get("inputSchema", {}) or {}
        # also inspect parameter descriptions
        for prop in (schema.get("properties") or {}).values():
            if isinstance(prop, dict):
                candidates.append(str(prop.get("description", "")))
        matches: list[InjectionMatch] = []
        for c in candidates:
            matches.extend(scan_string(c))
        if matches:
            findings[name] = matches
    return findings
