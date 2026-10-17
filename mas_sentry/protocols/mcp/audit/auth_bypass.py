# SPDX-License-Identifier: AGPL-3.0-or-later
"""An authorization boundary the target announces and does not apply.

Source: CVE-2026-59822 (`litellm` < 1.84.0, CWE-287 and CWE-306, CVSS 4.0 8.8;
GHSA-7488-6r32-c95q), the first MCP defect added to CISA's Known Exploited
Vulnerabilities catalog, exploitation confirmed. Read off the published packages
rather than off a write-up: 1.83.9 and 1.84.0 from PyPI, file
`litellm/proxy/_experimental/mcp_server/auth/user_api_key_auth_mcp.py`.

The class is the sibling of `authz_desync` one layer down. There, a filter was
honoured by `tools/list` and not by `tools/call`. Here the boundary itself is
announced by a 401 and not applied to the session: key validation runs, fails,
and its failure is replaced with an empty `UserAPIKeyAuth()`. The scanner asks
the same kind of question in both - does the restriction this target declared
actually hold - and reads the answer off the wire rather than off a config.

Two forms, both read from the published diff rather than guessed:

  **Any Authorization value.** `_get_oauth2_headers_from_headers` takes any
  header whose name starts with `authorization`, whatever its value, and the
  OAuth2 passthrough fallback turns a failed validation into a session. There is
  no prefix to match, no JWT shape, no `sk-` to guess, so one form of probe
  covers it - and two generated tokens rather than one, because a single token
  that worked could have been a real key by accident while two cannot both be.
  A target that answers the two differently is saying something this probe
  cannot read, and it says so instead of guessing (R-7.5).

  **A public-route marker.** The same fix closed a second defect: the
  public-route test was `".well-known" in str(request.url)`, a substring of the
  whole URL, so appending `?.well-known` to any MCP route made it public. 1.84.0
  matches `request.url.path.startswith("/.well-known/")`. Its comment names
  three vectors - query string, hostname, deeper URL segment - and only the
  query form changes exactly one variable from the baseline request: a hostname
  is not this scanner's to choose, and a deeper path segment changes the route,
  so a 404 would read as a refusal the gate never made.

**Read differentially, against a baseline taken from the same target in the
same scan.** The baseline is an attempt with no credential at all. Without it
an admitted session proves nothing: a server that asks for nothing admits every
attempt, which is a legitimate local deployment and not a bypassed boundary
(R-2.4). The finding is the difference between the two - refused with nothing,
admitted with anything.

**Nothing here executes a tool body.** Admission is established by `initialize`
and `tools/list`, the two calls that tell a caller it holds a session, and
neither runs a tool. `tools/call` is never sent, which is why the rig's only
tool writes a marker file that every case asserts is absent (R-7.6): the claim
is held to the disk rather than to this paragraph.

**Severity HIGH, not CRITICAL**, by the first source: CVSS 8.8 from the CNA and
8.2 from NVD, and a scan that reaches a listing does not know what the tools
behind it do. R-2.13 applied to severity, as in `authz_desync`.

CWE-287 is the CNA's attribution and the one carried here. CWE-289
(Authentication Bypass by Alternate Name) describes the marker form more
closely - a decision made from a resource name whose alternate forms are not
all checked - but no first source names it for this CVE, so it is recorded here
and not asserted in the taxonomy.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Protocol

# Two references, generated per scan. Long enough that a collision with a real
# key is not a thing that happens, short enough to read in a report.
_TOKEN_BYTES = 16

# The substring 1.83.9 matched anywhere in the URL. Appended as a query so the
# path, method and headers all stay exactly as the baseline sent them.
_ROUTE_MARKER = ".well-known"

# What an operator can act on, and no more. An admitted session is reported by
# what it reached, not by the inventory it exposes: the tool names behind a
# boundary are the target's, and R-7.3 keeps them out of the report.
_MAX_OUTCOME_CHARS = 200


@dataclass(frozen=True, slots=True)
class SessionAttempt:
    """What one unauthenticated attempt at a session got.

    `admitted` is the verdict; `outcome` is what it was read from, so a reviewer
    can derive the verdict again instead of trusting it (R-7.2).
    """

    label: str
    admitted: bool
    outcome: str

    @property
    def clipped(self) -> str:
        return self.outcome[:_MAX_OUTCOME_CHARS]


class SessionOpener(Protocol):
    """Opens one MCP session and reports whether it was admitted.

    Injected for the reason `Fetcher` is injected in `auth_prm`: these are new
    connections rather than calls on the scan's client, so nothing the client
    enforces applies to them, and a Protocol keeps the probe drivable without a
    socket.
    """

    def attempt(self, label: str, url: str, headers: dict[str, str]) -> SessionAttempt: ...


@dataclass(frozen=True, slots=True)
class BypassFinding:
    check: str
    severity: str
    detail: str
    evidence: dict[str, str] = field(default_factory=dict)


def _evidence(baseline: SessionAttempt, admitted: SessionAttempt, form: str) -> dict[str, str]:
    """Both sides of the comparison the verdict was drawn from."""
    return {
        "probe_form": form,
        "without_credential": baseline.clipped,
        "with_credential": admitted.clipped,
    }


def probe_auth_bypass(target_url: str, opener: SessionOpener) -> list[BypassFinding]:
    """Ask whether the boundary this target announced applies to a session.

    Four attempts, in this order: no credential, two generated bearer tokens,
    and the route marker. The baseline comes first because every later verdict
    is a difference from it.
    """
    baseline = opener.attempt("no-credential", target_url, {})
    if baseline.admitted:
        # No boundary to bypass. Reported rather than dropped, and as the good
        # news it is: a server that asks for nothing is a legitimate local
        # deployment, and calling it bypassed would be a finding we invented.
        return [
            BypassFinding(
                check="auth_bypass_unverified",
                severity="INFO",
                detail=(
                    f"{target_url} admitted a session with no credential at all, so there is no announced "
                    "boundary to test. Nothing was bypassed - this scan simply ran unauthenticated"
                ),
                evidence={
                    "probe_form": "none",
                    "reason": "no-boundary-declared",
                    "without_credential": baseline.clipped,
                },
            )
        ]

    out: list[BypassFinding] = []
    first = opener.attempt("bearer-1", target_url, {"Authorization": f"Bearer {secrets.token_urlsafe(_TOKEN_BYTES)}"})
    second = opener.attempt("bearer-2", target_url, {"Authorization": f"Bearer {secrets.token_urlsafe(_TOKEN_BYTES)}"})

    if first.admitted and second.admitted:
        out.append(
            BypassFinding(
                check="auth_bypass",
                severity="HIGH",
                detail=(
                    f"{target_url} refused a session with no credential and granted one to two freshly "
                    "generated bearer tokens. Key validation is reached and its failure is not applied, so any "
                    "value in the Authorization header is an authenticated session. No tool was called"
                ),
                evidence=_evidence(baseline, first, "any-bearer-value"),
            )
        )
    elif first.admitted != second.admitted:
        # One token in and one out cannot both be explained by the target's
        # rule. Either it keyed on the value - which would make one of these a
        # real key, and this scan cannot establish that - or it is not stable
        # across attempts. Both are bounds on the observation, not findings.
        out.append(
            BypassFinding(
                check="auth_bypass_unverified",
                severity="MEDIUM",
                detail=(
                    f"{target_url} answered two freshly generated bearer tokens differently, so the rule it "
                    "applied cannot be read from this comparison. Whether the boundary holds is unestablished, "
                    "not established clean"
                ),
                evidence={
                    "probe_form": "any-bearer-value",
                    "reason": "references-disagree",
                    "without_credential": baseline.clipped,
                    "with_credential": f"{first.label}: {first.clipped} | {second.label}: {second.clipped}",
                },
            )
        )

    marker = opener.attempt("route-marker", f"{target_url}?{_ROUTE_MARKER}", {})
    if marker.admitted:
        out.append(
            BypassFinding(
                check="auth_bypass",
                severity="HIGH",
                detail=(
                    f"{target_url} refused a session with no credential and granted one when "
                    f"`?{_ROUTE_MARKER}` was appended to the same URL. The public-route test matches a "
                    "substring of the whole URL rather than the path, so any route can be marked public by a "
                    "caller. No tool was called"
                ),
                evidence=_evidence(baseline, marker, "public-route-marker"),
            )
        )

    if not out:
        out.append(
            BypassFinding(
                check="auth_bypass_unverified",
                severity="INFO",
                detail=(
                    f"{target_url} refused every form this probe sent: no credential, two generated bearer "
                    "tokens, and a public-route marker on the same URL. The announced boundary held against "
                    "all four"
                ),
                evidence={
                    "probe_form": "all",
                    "reason": "refused-every-form",
                    "without_credential": baseline.clipped,
                    "with_credential": f"{first.label}: {first.clipped} | {marker.label}: {marker.clipped}",
                },
            )
        )
    return out


class McpSessionOpener:
    """Opens each attempt as its own session, under bounds of its own.

    One connection per attempt rather than header overrides on the scan's
    client, because the defect is about which session a target grants: a probe
    riding an established session would be asking a question the handshake has
    already answered.

    These requests do not go through the JSON-RPC client, so the scan budget is
    wired up here or it does not apply - the same bargain `HttpFetcher` strikes
    for its metadata reads.
    """

    def __init__(self, timeout: float = 10.0, deadline: float = 20.0, budget: object | None = None) -> None:
        self.timeout = timeout
        self.deadline = deadline
        self.budget = budget

    def attempt(self, label: str, url: str, headers: dict[str, str]) -> SessionAttempt:
        from ..client import McpClient
        from ..errors import TargetUnreachable
        from ..transport_http import HttpConfig, open_http

        spend = getattr(self.budget, "spend", None)
        if spend is not None and not spend(f"session {label}"):
            return SessionAttempt(
                label=label,
                admitted=False,
                outcome="the scan budget ran out before this attempt; this is a scanner bound",
            )
        config = HttpConfig(url=url, headers=headers or None, timeout=self.timeout, deadline=self.deadline)
        try:
            with open_http(config) as transport:
                client = McpClient(transport)
                info = client.connect()
                tools = client.list_tools()
        except TargetUnreachable as exc:
            return SessionAttempt(label=label, admitted=False, outcome=f"refused: {exc}")
        return SessionAttempt(
            label=label,
            admitted=True,
            outcome=f"initialize succeeded (server {info.name or 'unnamed'}) and tools/list returned {len(tools)}",
        )
