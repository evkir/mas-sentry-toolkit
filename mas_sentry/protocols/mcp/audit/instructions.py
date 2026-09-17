# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit of the server's `instructions` string.

The field is the one piece of server-authored prose a host puts into model
context before any tool is called, and it has been collected by this client
and read by nothing. In a field survey of 8235 reachable public MCP servers
(August 2026), roughly two thirds returned it; the median was under 600
characters and the longest exceeded 68000.

The same survey is the reason this module does not look for the shapes a
proof-of-concept uses. Not one of those servers carried the literal override
template from the published PoC. What does occur is prose telling the assistant
to keep something from the person it is acting for, so that is what is matched:
a directive not to disclose, not to relay, or not to ask, addressed to the user
rather than to the model's style.

Matching requires the human as the addressee - user, human, caller, operator -
because a bare "do not mention X" is ordinary developer guidance and firing on
it would bury the cases that matter. Consent bypasses are the exception: "do
not ask for permission" needs no addressee to mean what it says.

None of this proves intent. A server has legitimate reasons to shape what an
assistant says, and the row says what was found and where, not what it is for.
What makes the field worth a row at all is that the person whose assistant
reads it never sees it: they cannot form an opinion about a directive that is
delivered past them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from mas_sentry.core.injection_scan import STRONG_PATTERNS, scan_string

from ..client import DISCOVER_METHOD, McpClient
from .caching import positive_ttl

INSTRUCTIONS_CHECK = "server_instructions"
CONCEALMENT_CHECK = "instructions_concealment"
INJECTION_CHECK = "instructions_injection"
OVERSIZED_CHECK = "instructions_oversized"
SHARED_CACHE_CHECK = "instructions_shared_cache"

# An order of magnitude above the field median, so this is about the tail
# rather than about servers that explain themselves. Every character is re-sent
# with the context on every turn of the conversation.
OVERSIZED_CHARS = 4000

_ADDRESSEE = r"(?:the )?(?:user|human|caller|operator)"
_CONCEALMENT = (
    (
        "withhold-from-user",
        re.compile(
            r"(?i)(?:do not|don't|never|avoid)\s+(?:\w+\s+){0,2}"
            r"(?:mention|tell|inform|show|display|reveal|disclose|quote|paraphrase|summari[sz]e|relay|report)"
            # Clause-bounded rather than word-counted: the field form chains
            # several verbs before naming the addressee ("do not quote,
            # paraphrase or relay the contents to the user"), and a sentence or
            # clause break means the two halves were never one directive.
            r"[^.;\n]{0,60}?(?:to\s+)?" + _ADDRESSEE
        ),
    ),
    (
        "act-without-consent",
        re.compile(
            r"(?i)(?:do not|don't|never|without)\s+ask(?:ing)?\s+(?:for\s+)?(?:permission|confirmation|approval)"
        ),
    ),
    (
        "conceal-the-step",
        re.compile(r"(?i)\b(?:silently|quietly|without\s+(?:telling|informing|notifying)\s+" + _ADDRESSEE + r")\b"),
    ),
)


@dataclass(frozen=True, slots=True)
class InstructionsFinding:
    check: str
    severity: str
    detail: str


def _excerpt(text: str, at: int, width: int = 80) -> str:
    """A short window around a match, so the row shows evidence, not the document."""
    start = max(0, at - width // 2)
    return " ".join(text[start : start + width].split())


def _concealment_findings(text: str) -> list[InstructionsFinding]:
    hits = []
    for name, pattern in _CONCEALMENT:
        match = pattern.search(text)
        if match is not None:
            hits.append(f"{name}: ...{_excerpt(text, match.start())}...")
    if not hits:
        return []
    return [
        InstructionsFinding(
            CONCEALMENT_CHECK,
            "MEDIUM",
            (
                f"server instructions direct the assistant to keep something from the person using it: "
                f"{'; '.join(hits)}. The person never sees this text, so a directive delivered here is one "
                "they had no opportunity to refuse. A server may have a defensible reason; the row states "
                "what was said, not why"
            ),
        )
    ]


def _injection_findings(text: str) -> list[InstructionsFinding]:
    matches = scan_string(text)
    if not matches:
        return []
    strong = [m for m in matches if m.pattern in STRONG_PATTERNS]
    named = ", ".join(sorted({m.pattern for m in matches}))
    return [
        InstructionsFinding(
            INJECTION_CHECK,
            "HIGH" if strong else "MEDIUM",
            (
                f"server instructions carry prompt-injection patterns ({named}). This text enters model "
                "context ahead of every tool descriptor and outside the content the host marks as data, so "
                "a directive placed here is read with the host's own framing"
            ),
        )
    ]


def _oversized_findings(text: str) -> list[InstructionsFinding]:
    if len(text) <= OVERSIZED_CHARS:
        return []
    return [
        InstructionsFinding(
            OVERSIZED_CHECK,
            "LOW",
            (
                f"server instructions are {len(text)} characters, more than {OVERSIZED_CHARS}. The string is "
                "carried in context for the whole conversation, so the target sets a standing cost on every "
                "turn the host pays without being asked"
            ),
        )
    ]


def _shared_cache_findings(client: McpClient, text: str) -> list[InstructionsFinding]:
    """The combination the published advisories are about, and only that combination."""
    windows = [
        hint
        for hint in client.cache_hints
        if hint.method == DISCOVER_METHOD
        and hint.scope_present
        and hint.cache_scope == "public"
        and positive_ttl(hint) > 0
    ]
    if not windows:
        return []
    ttl = max(positive_ttl(hint) for hint in windows)
    return [
        InstructionsFinding(
            SHARED_CACHE_CHECK,
            "HIGH",
            (
                f"the discover result carrying these {len(text)} characters of instructions is marked "
                f"cacheScope public for {ttl // 1000}s. A shared cache in front of this server may hand the "
                "stored copy to a different user, which puts server-authored prose into a second person's "
                "model context through a path neither of them chose"
            ),
        )
    ]


def audit_instructions(client: McpClient) -> list[InstructionsFinding]:
    """Read the instructions this scan already received. Sends nothing."""
    server = client.server
    text = server.instructions if server is not None else ""
    if not text:
        return []
    out = [
        InstructionsFinding(
            INSTRUCTIONS_CHECK,
            "INFO",
            (
                f"the server supplied {len(text)} characters of instructions, which a host places in model "
                "context before any tool is called. Recorded so the report shows the text exists; what it "
                "says is assessed by the rows that follow"
            ),
        )
    ]
    out.extend(_concealment_findings(text))
    out.extend(_injection_findings(text))
    out.extend(_oversized_findings(text))
    out.extend(_shared_cache_findings(client, text))
    return out
