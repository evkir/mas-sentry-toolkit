# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conformance audit of the SEP-2549 freshness declaration.

Every value read here arrived inside an answer the enumeration already asked
for, so this module sends nothing. What it reports is what the target said
about how long its answers stay fresh and who may be served them - a
declaration, not a probe result.

Scope is narrow on purpose, because the ecosystem's defaults are not defects.
`ttlMs: 0` is what the Python SDK sends when a handler says nothing, and go-sdk
stamps `cacheScope: "public"` with `ttlMs: 0` on generated results, which is why
a bare `public` earns no row here. The rust `rmcp` macro-generated handler sends
neither field at all, so an absent `ttlMs` is common in the field rather than
rare - it is still a MUST the server skipped, and it is reported at LOW because
a client lands on 0 by rule rather than by the server's statement.

What is reported, and why each is a fact rather than a guess:

- an absent `ttlMs` on a 2026-07-28 answer: the revision requires the field.
- a `ttlMs` that is negative or not an integer: the SEP requires `>= 0`, and a
  client SHOULD read a negative one as 0. The raw value is carried into the row
  because a repaired one would leave nothing to see.
- a `cacheScope` outside `"public"`/`"private"`: strict clients reject the
  whole listing over it, which turns a conformance slip into a failed tool
  discovery against an otherwise working server.
- two pages of one listing walk declaring different scopes: the SEP requires
  one scope across every page of one request. A false positive is not
  available here - the disagreement is between two answers the target sent
  itself, within one walk this client performed.

Two further rows are about exposure rather than conformance, and both are
written to stay quiet against a conformant default:

- `cacheScope: "public"` with a ttl above zero. Public alone is what go-sdk
  stamps on generated results and means nothing on its own; public with a
  lifetime is the combination a shared gateway reads as permission to hand
  this answer to a user who never asked the server for it. Zero closes the
  window, which is why the pair is required.
- a listing dated further ahead than an hour while the server declares no
  change notification for it. The server asked clients to hold the inventory
  and kept no way to say it moved, so a descriptor swapped inside that window
  reaches a client that has no reason to look again. Where the server does
  declare `listChanged` (or `subscribe`, for a read) there is a channel and no
  row.

`server/discover` is left out of the second one on purpose: the protocol gives
it no change notification at all, so every long-lived discover would produce a
row that says more about the SEP than about the target.

A declared `listChanged` closes the stale window here, and that is a boundary
rather than a belief. Measured against the reference SDK, a server declares the
capability on every section and then rewrites a descriptor mid-scan announcing
nothing, so the declaration states intent and guarantees no notification. The
pairing is still the right one for this module: firing on a declared channel
would fire on every server built with that SDK. The broken promise is reported
where it can be proven - `tool_mutation` sees the descriptor move and marks the
row `announced=False`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..client import CacheHint, McpClient

# The revision that introduced the fields. A server speaking an earlier one is
# not silent about freshness; it has no freshness fields to be silent with.
CACHING_REVISION = "2026-07-28"

TTL_MISSING_CHECK = "cache_ttl_missing"
TTL_INVALID_CHECK = "cache_ttl_invalid"
SCOPE_INVALID_CHECK = "cache_scope_invalid"
SCOPE_SPLIT_CHECK = "cache_scope_split"
PUBLIC_WINDOW_CHECK = "cache_public_window"
STALE_WINDOW_CHECK = "cache_stale_window"

VALID_SCOPES = ("public", "private")

# An hour. Chosen as an order of magnitude rather than measured: it is longer
# than an agent session, so an inventory dated past it is one a client will act
# on for the whole of its working life without asking again. A shorter bound
# would fire on every server that caches sensibly.
LONG_TTL_MS = 3_600_000

# The capability that gives a client a reason to look again, per method. A
# listing has listChanged; a read has subscribe. server/discover has neither,
# and is absent from this table because the protocol gives it none.
CHANGE_CHANNELS = {
    "tools/list": ("tools", "listChanged"),
    "prompts/list": ("prompts", "listChanged"),
    "resources/list": ("resources", "listChanged"),
    "resources/templates/list": ("resources", "listChanged"),
    "resources/read": ("resources", "subscribe"),
}


@dataclass(frozen=True, slots=True)
class CachingFinding:
    check: str
    severity: str
    detail: str


def _declares_caching(client: McpClient) -> bool:
    """True when the target answered on a revision that carries these fields.

    Read off the server's own answer where there is one. A client that fell
    back to the handshake never negotiated the revision, and a modern route
    retried onto an older version the target offered is older too - in both
    cases an absent field is the shape of the protocol, not a skipped MUST.
    """
    if not client.is_modern:
        return False
    stated = client.server.protocol_version if client.server is not None else ""
    return (stated or client.protocol_version) >= CACHING_REVISION


def _where(hint: CacheHint) -> str:
    """Name the answer a hint came from, in the terms the target would use."""
    if hint.subject:
        return f"{hint.method} ({hint.subject})"
    return hint.method


def _ttl_findings(hints: list[CacheHint]) -> list[CachingFinding]:
    missing: list[str] = []
    invalid: list[str] = []
    for hint in hints:
        if not hint.ttl_present:
            missing.append(f"{_where(hint)} walk {hint.walk} page {hint.page}")
            continue
        ttl = hint.ttl_ms
        if isinstance(ttl, bool) or not isinstance(ttl, int):
            invalid.append(f"{_where(hint)} sent ttlMs {ttl!r} ({type(ttl).__name__})")
        elif ttl < 0:
            invalid.append(f"{_where(hint)} sent ttlMs {ttl}")
    out: list[CachingFinding] = []
    if missing:
        out.append(
            CachingFinding(
                TTL_MISSING_CHECK,
                "LOW",
                (
                    f"{len(missing)} cacheable answer(s) carried no ttlMs on {CACHING_REVISION}, which requires "
                    f"it: {', '.join(missing[:6])}. A client reading them falls back to 0 by rule rather than "
                    "because the server said so, and cannot tell this server from one that declared "
                    "immediate staleness"
                ),
            )
        )
    if invalid:
        out.append(
            CachingFinding(
                TTL_INVALID_CHECK,
                "LOW",
                (
                    f"ttlMs must be an integer >= 0; {', '.join(invalid[:6])}. Values are reported as sent. A "
                    "conformant client reads a negative ttl as 0, so the practical effect is a freshness "
                    "statement the server did not mean to make"
                ),
            )
        )
    return out


def _scope_findings(hints: list[CacheHint]) -> list[CachingFinding]:
    out: list[CachingFinding] = []
    invalid = [
        f"{_where(hint)} sent cacheScope {hint.cache_scope!r}"
        for hint in hints
        if hint.scope_present and hint.cache_scope not in VALID_SCOPES
    ]
    if invalid:
        out.append(
            CachingFinding(
                SCOPE_INVALID_CHECK,
                "LOW",
                (
                    f"cacheScope is defined as public or private; {', '.join(invalid[:6])}. A strict client "
                    "rejects the whole listing over this, so a server that is otherwise working fails tool "
                    "discovery; a lenient one picks a sharing policy the server never stated"
                ),
            )
        )
    out.extend(_split_findings(hints))
    return out


def _split_findings(hints: list[CacheHint]) -> list[CachingFinding]:
    """One scope per listing walk, per the SEP. Two is the target contradicting itself."""
    walks: dict[tuple[str, int], list[CacheHint]] = {}
    for hint in hints:
        walks.setdefault((hint.method, hint.walk), []).append(hint)
    out: list[CachingFinding] = []
    for (method, walk), pages in sorted(walks.items()):
        if len(pages) < 2:
            continue
        declared = {(page.scope_present, page.cache_scope) for page in pages}
        if len(declared) < 2:
            continue
        shown = ", ".join(
            f"page {page.page}: {page.cache_scope!r}" if page.scope_present else f"page {page.page}: absent"
            for page in sorted(pages, key=lambda p: p.page)
        )
        out.append(
            CachingFinding(
                SCOPE_SPLIT_CHECK,
                "MEDIUM",
                (
                    f"{method} declared more than one cacheScope within listing walk {walk} ({shown}). The SEP "
                    "requires the same scope on every page of one request, and a cache that stores the pages "
                    "under different sharing rules holds one inventory split across two policies. The pages "
                    "compared here came from one walk this scan performed"
                ),
            )
        )
    return out


def positive_ttl(hint: CacheHint) -> int:
    """The declared lifetime, or 0 for anything that is not a usable number.

    Public because the instructions audit asks the same question of the discover
    hint, and a second copy of this rule would be a second place to get the
    bool-is-not-an-int case wrong.
    """
    ttl = hint.ttl_ms
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        return 0
    return ttl


def _announces_change(capabilities: dict[str, Any], method: str) -> bool:
    """True when the server declared a way to tell a client the answer moved."""
    channel = CHANGE_CHANNELS.get(method)
    if channel is None:
        return True
    section, flag = channel
    declared = capabilities.get(section)
    return isinstance(declared, dict) and declared.get(flag) is True


def _shared_window(hint: CacheHint) -> bool:
    """Public is the permission; a lifetime above zero is what makes it usable."""
    return hint.scope_present and hint.cache_scope == "public" and positive_ttl(hint) > 0


def _exposure_findings(client: McpClient, hints: list[CacheHint]) -> list[CachingFinding]:
    """What the declaration permits, as opposed to whether it is well formed."""
    shared = [f"{_where(hint)} for {positive_ttl(hint) // 1000}s" for hint in hints if _shared_window(hint)]
    capabilities = client.server.capabilities if client.server is not None else {}
    unannounced: dict[str, tuple[str, int]] = {}
    for hint in hints:
        ttl = positive_ttl(hint)
        if ttl < LONG_TTL_MS or _announces_change(capabilities, hint.method):
            continue
        where = _where(hint)
        _, seen = unannounced.get(where, (hint.method, 0))
        unannounced[where] = (hint.method, max(seen, ttl))

    out: list[CachingFinding] = []
    if shared:
        out.append(
            CachingFinding(
                PUBLIC_WINDOW_CHECK,
                "MEDIUM",
                (
                    f"cacheScope public with a lifetime above zero: {', '.join(sorted(set(shared))[:6])}. A "
                    "shared cache in front of this server may serve the stored answer to a user who never "
                    "asked for it, for the whole of that window. The scan was unauthenticated, so what the "
                    "answer contains for an authenticated caller is unknown - the permission is the finding"
                ),
            )
        )
    for where, (method, ttl) in sorted(unannounced.items()):
        section, flag = CHANGE_CHANNELS[method]
        out.append(
            CachingFinding(
                STALE_WINDOW_CHECK,
                "MEDIUM",
                (
                    f"{where} is dated {ttl // 1000}s ahead while the server declares no {section}.{flag}. A "
                    "client is asked to hold this answer with no channel to be told it moved, so a descriptor "
                    "swapped inside the window reaches it with nothing prompting a second look"
                ),
            )
        )
    return out


def audit_caching(client: McpClient) -> list[CachingFinding]:
    """Read the freshness declaration this scan already collected.

    Returns nothing for a target that never spoke the revision carrying the
    fields: silence about caching is only a fact when the protocol asked for
    speech.
    """
    if not _declares_caching(client) or not client.cache_hints:
        return []
    hints = list(client.cache_hints)
    return _ttl_findings(hints) + _scope_findings(hints) + _exposure_findings(client, hints)
