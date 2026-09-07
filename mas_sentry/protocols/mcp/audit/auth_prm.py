# SPDX-License-Identifier: AGPL-3.0-or-later
"""RFC 9728: what a server publishes about how to authenticate to it.

A server that refuses an unauthenticated call points, in `WWW-Authenticate`,
at a document describing its authorization servers. That document is the second
step of the discovery chain and the last one this module walks: it is read and
audited, and the issuers it names are inspected as strings but never fetched.

Not fetching them is the point. RFC 9728 Section 7.7 warns that a client
following `authorization_servers` into a network it has no prior knowledge of
is a server-side request forgery waiting to happen, and the party at risk is
the operator running this scanner, not the target. A hostile server writing an
internal address there would have MST reach into the operator's network on its
behalf - so an issuer outside the scan's allowlist is reported as a finding
about the target rather than followed as an instruction.

What the audit asserts, and where each assertion comes from:

  Section 1.2   the resource identifier is a URL that uses the https scheme,
                and jwks_uri carries the same MUST explicitly
  Section 3     a resource supporting metadata MUST publish it at the
                well-known location derived from its identifier
  Section 3.3   the `resource` value MUST be identical to the URL the client
                used; if it is not, the document MUST NOT be used
  Section 2     bearer_methods_supported is drawn from header, body and query,
                and query means the token travels in the URL
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

WELL_KNOWN = "/.well-known/oauth-protected-resource"

# The document is small by construction. Anything larger is a body meant to
# cost us something, not a set of metadata parameters.
MAX_DOCUMENT_CHARS = 256 * 1024

# Where cleartext is a deployment rather than a defect.
_LOOPBACK_NAMES = frozenset({"localhost"})


@dataclass(frozen=True, slots=True)
class FetchResult:
    """What came back from one metadata request, or why nothing did."""

    url: str
    status: int = 0
    text: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200 and not self.error


class Fetcher(Protocol):
    """Reads one metadata URL. Injected so the audit can be driven without a socket."""

    def get(self, url: str) -> FetchResult: ...


class HttpFetcher:
    """Reads metadata over HTTP, under the same bounds every other request has.

    Its own deadline and cap rather than the transport's: these requests do not
    go through the JSON-RPC client, and a metadata URL is written by the target
    exactly like a tool argument is.

    The scope guard is the SSRF answer from RFC 9728 Section 7.7. The address
    came from the target, so it is checked against the same allowlist that
    decides what this scanner is allowed to touch - a server naming an internal
    host gets a refusal it can observe, not a request made on its behalf.
    """

    def __init__(self, timeout: float = 10.0, scope_confirmed: bool = False) -> None:
        self.timeout = timeout
        self.scope_confirmed = scope_confirmed

    def get(self, url: str) -> FetchResult:
        import httpx

        from mas_sentry.core.scope import ScopeViolation, assert_in_scope

        host = urlsplit(url).hostname or ""
        try:
            assert_in_scope(host, confirmed=self.scope_confirmed)
        except ScopeViolation:
            return FetchResult(url=url, error="outside the scan allowlist; not fetched")
        try:
            r = httpx.get(url, timeout=self.timeout, follow_redirects=False)
        except httpx.HTTPError as exc:
            return FetchResult(url=url, error=str(exc) or type(exc).__name__)
        return FetchResult(url=url, status=r.status_code, text=r.text[: MAX_DOCUMENT_CHARS + 1])


@dataclass(frozen=True, slots=True)
class AuthFinding:
    """One row about how the target described its authorization boundary."""

    check: str
    severity: str
    detail: str


def is_loopback(host: str) -> bool:
    """True for an address that never leaves the machine.

    Cleartext to a loopback address is how every local MCP server and every rig
    in this repository runs, so flagging it would fire the highest severity
    here on the most common honest configuration.
    """
    name = host.split("%")[0].strip("[]").lower()
    if name in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def discovery_urls(target: str, pointer: str = "") -> list[str]:
    """Where to look for the document, in the order a client would look.

    The pointer the server put in `WWW-Authenticate` comes first because it is
    what the server asked us to use. The path-based form comes next: RFC 9728
    Section 3 inserts the well-known string between the host component and the
    path, so a resource at /deep/mcp publishes at
    /.well-known/oauth-protected-resource/deep/mcp and not at the root. The
    root form is the fallback, and is correct only for a resource identifier
    with no path at all.
    """
    parts = urlsplit(target)
    base = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    path = parts.path.rstrip("/")
    out: list[str] = []
    if pointer:
        out.append(pointer)
    if not parts.netloc:
        return [pointer] if pointer else []
    if path or parts.query:
        suffix = path + (f"?{parts.query}" if parts.query else "")
        out.append(f"{base}{WELL_KNOWN}{suffix}")
    out.append(f"{base}{WELL_KNOWN}")
    seen: set[str] = set()
    unique: list[str] = []
    for url in out:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def _same_resource(declared: str, scanned: str) -> bool:
    """Compare two resource identifiers the way Section 3.3 asks them to be compared.

    Only the host case and a trailing slash are normalised away. The RFC calls
    for a code-point comparison, and anything cleverer here - resolving a name,
    ignoring a port - would quietly accept the mismatch the check exists to
    find.
    """
    left, right = urlsplit(declared), urlsplit(scanned)
    return (
        left.scheme == right.scheme
        and left.netloc.lower() == right.netloc.lower()
        and left.path.rstrip("/") == right.path.rstrip("/")
        and left.query == right.query
    )


def _cleartext_urls(document: dict[str, Any]) -> list[str]:
    """Every URL in the document that travels in the clear off this machine."""
    candidates: list[str] = []
    resource = document.get("resource")
    if isinstance(resource, str):
        candidates.append(resource)
    jwks = document.get("jwks_uri")
    if isinstance(jwks, str):
        candidates.append(jwks)
    servers = document.get("authorization_servers")
    if isinstance(servers, list):
        candidates.extend(item for item in servers if isinstance(item, str))
    out = []
    for url in candidates:
        parts = urlsplit(url)
        if parts.scheme == "http" and not is_loopback(parts.hostname or ""):
            out.append(url)
    return out


def _read_document(results: list[FetchResult]) -> tuple[dict[str, Any] | None, FetchResult | None]:
    """The first answer that is actually a metadata document."""
    for result in results:
        if not result.ok:
            continue
        if len(result.text) > MAX_DOCUMENT_CHARS:
            continue
        try:
            parsed = json.loads(result.text)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed, result
    return None, None


def audit_protected_resource(
    target: str,
    pointer: str,
    fetcher: Fetcher,
    refused: bool,
) -> list[AuthFinding]:
    """Walk the discovery chain and report what the document says.

    `refused` is whether the server actually demanded authentication. A server
    that never asked for a token and publishes no metadata is not defective and
    gets no row: a check that fires on every target without OAuth is noise, and
    most MCP servers today have none.
    """
    attempts = [fetcher.get(url) for url in discovery_urls(target, pointer)]
    document, source = _read_document(attempts)

    if document is None:
        if not refused:
            return []
        tried = "; ".join(f"{a.url} -> {a.error or a.status}" for a in attempts)
        return [
            AuthFinding(
                check="auth_discovery",
                severity="MEDIUM",
                detail=(
                    f"The server demanded authentication but published no readable protected resource "
                    f"metadata (RFC 9728 Section 3). Tried: {tried}. A client cannot find the "
                    "authorization server from here, and nothing behind the boundary was assessed"
                ),
            )
        ]

    out: list[AuthFinding] = []
    resource = document.get("resource")
    if not isinstance(resource, str) or not resource:
        out.append(
            AuthFinding(
                check="auth_discovery",
                severity="MEDIUM",
                detail=(
                    f"The metadata at {source.url if source else target} omits `resource`, which RFC 9728 "
                    "Section 2 makes REQUIRED. Section 3.3 has a client validate that value against the URL "
                    "it called, so a conforming client must discard this document"
                ),
            )
        )
    elif not _same_resource(resource, target):
        out.append(
            AuthFinding(
                check="auth_resource_binding",
                severity="MEDIUM",
                detail=(
                    f"The metadata declares resource {resource}, which is not the URL this scan called "
                    f"({target}). RFC 9728 Section 3.3 requires them to be identical and says the document "
                    "MUST NOT be used otherwise, so a conforming client stops here. A reverse proxy in "
                    "front of the server produces this legitimately - confirm which URL clients reach "
                    "before treating it as a defect"
                ),
            )
        )

    cleartext = _cleartext_urls(document)
    if cleartext:
        out.append(
            AuthFinding(
                check="auth_transport",
                severity="HIGH",
                detail=(
                    f"The metadata names {', '.join(cleartext)} over http, off loopback. RFC 9728 defines a "
                    "resource identifier as a URL using the https scheme, and requires https of jwks_uri "
                    "outright; a token obtained or presented across these addresses is readable in transit"
                ),
            )
        )

    methods = document.get("bearer_methods_supported")
    if isinstance(methods, list) and "query" in methods:
        out.append(
            AuthFinding(
                check="auth_bearer_methods",
                severity="MEDIUM",
                detail=(
                    "The metadata advertises the `query` bearer method, which puts the access token in the "
                    "request URL (RFC 6750 Section 2.3). URLs are written to proxy logs, browser history "
                    "and Referer headers, so a token presented this way outlives the request that carried it"
                ),
            )
        )
    return out
