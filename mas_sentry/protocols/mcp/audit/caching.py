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

Nothing in this module asserts that data leaked. Whether a declaration opens a
window an attacker can stand in is a separate question from whether it
conforms, and it is asked elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..client import CacheHint, McpClient

# The revision that introduced the fields. A server speaking an earlier one is
# not silent about freshness; it has no freshness fields to be silent with.
CACHING_REVISION = "2026-07-28"

TTL_MISSING_CHECK = "cache_ttl_missing"
TTL_INVALID_CHECK = "cache_ttl_invalid"
SCOPE_INVALID_CHECK = "cache_scope_invalid"
SCOPE_SPLIT_CHECK = "cache_scope_split"

VALID_SCOPES = ("public", "private")


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


def audit_caching(client: McpClient) -> list[CachingFinding]:
    """Read the freshness declaration this scan already collected.

    Returns nothing for a target that never spoke the revision carrying the
    fields: silence about caching is only a fact when the protocol asked for
    speech.
    """
    if not _declares_caching(client) or not client.cache_hints:
        return []
    hints = list(client.cache_hints)
    return _ttl_findings(hints) + _scope_findings(hints)
