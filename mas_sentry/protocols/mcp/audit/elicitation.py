# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit of the consent surface: what the server asks a human to do.

An elicitation is the one point in MCP where a server reaches past the agent
and addresses the operator directly - either sending a browser somewhere in URL
mode, or asking for values typed into a form. Both are trust decisions made by
a person who sees only what the client renders, which is why the address and
the schema are worth reading rather than counting.

The findings here describe the request, never an answer to it. This client
declines every elicitation by never retrying, so nothing below completes a
flow, follows a redirect or fills a field.

Scope is deliberately narrow, because a check that fires on every honest OAuth
flow is noise. An off-origin consent URL is normal - that is what an identity
provider is - so it is reported at INFO and nothing more. What earns a real
severity is a surface the person cannot verify even in principle: cleartext,
credentials packed in front of the host, a bare address with no name behind it,
or a form asking for a secret that form mode is specified not to carry.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit

from ..client import ElicitationRequest, McpClient

# Matched against the property name for a HIGH, and against the description
# only for a MEDIUM. A name is what the server chose to call the field and is
# rarely accidental; a description is prose, and prose says "no password is
# required" as readily as it asks for one. Splitting them keeps a false
# positive off the severity that gets acted on.
_SECRET_MARKERS = (
    "api key",
    "api-key",
    "api_key",
    "apikey",
    "credential",
    "credit card",
    "cvv",
    "mnemonic",
    "passphrase",
    "passwd",
    "password",
    "private key",
    "private-key",
    "private_key",
    "recovery phrase",
    "secret",
    "seed phrase",
    "social security",
    "token",
)

# A consent page served over http on the loopback interface is how a locally
# spawned server does authorization, and flagging it would put a finding on
# every stdio target. It is not reachable by anyone but the operator.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

URL_CHECK = "elicitation_url"
FORM_CHECK = "elicitation_secret_field"


@dataclass(frozen=True, slots=True)
class ElicitationFinding:
    check: str
    severity: str
    detail: str


def _worst(current: str, candidate: str) -> str:
    return candidate if _ORDER[candidate] > _ORDER[current] else current


def _is_ip_literal(host: str) -> bool:
    try:
        ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _origin_host(client: McpClient) -> str:
    """The host the scan is aimed at, or empty when the transport has none.

    STDIO has no origin to compare against, so the off-origin observation is
    simply not made there rather than being made wrongly.
    """
    config = getattr(client.transport, "config", None)
    url = getattr(config, "url", "")
    if not isinstance(url, str) or not url:
        return ""
    return (urlsplit(url).hostname or "").lower()


def _audit_url(request: ElicitationRequest, origin_host: str) -> ElicitationFinding | None:
    if not request.url:
        return None
    parts = urlsplit(request.url)
    host = (parts.hostname or "").lower()
    loopback = host in _LOOPBACK_HOSTS
    severity = "INFO"
    reasons: list[str] = []

    if parts.username or parts.password:
        severity = _worst(severity, "HIGH")
        reasons.append("credentials are embedded ahead of the host, which is also how a link hides where it goes")
    if parts.scheme != "https" and not loopback:
        severity = _worst(severity, "HIGH")
        reasons.append(f"the scheme is {parts.scheme or 'absent'}, so whatever the person enters travels in the clear")
    if host and not loopback and _is_ip_literal(host):
        severity = _worst(severity, "MEDIUM")
        reasons.append("the host is a bare address, so there is no name for a certificate to bind or a person to check")
    if origin_host and host and host != origin_host:
        reasons.append(
            f"the address leaves the scanned origin ({origin_host}), which is expected of an identity provider"
        )

    if not reasons:
        return None
    return ElicitationFinding(
        check=URL_CHECK,
        severity=severity,
        detail=(
            f"{request.method} asked for consent at {request.url[:200]} "
            f"(message: {request.message[:120]!r}): " + "; ".join(reasons)
        ),
    )


def _audit_form(request: ElicitationRequest) -> ElicitationFinding | None:
    """Form mode is specified for non-sensitive input; a secret asked for here is the finding."""
    by_name: list[str] = []
    by_description: list[str] = []
    for name, description in request.fields:
        lowered = name.lower()
        if any(marker in lowered for marker in _SECRET_MARKERS):
            by_name.append(name)
            continue
        if any(marker in description.lower() for marker in _SECRET_MARKERS):
            by_description.append(name)
    if not by_name and not by_description:
        return None
    named = ", ".join(by_name + by_description)
    return ElicitationFinding(
        check=FORM_CHECK,
        severity="HIGH" if by_name else "MEDIUM",
        detail=(
            f"{request.method} raised a form-mode elicitation collecting {named} "
            f"(message: {request.message[:120]!r}). Form mode is specified for non-sensitive "
            "input, so a secret typed here reaches the client and whatever context it feeds."
        ),
    )


def audit_elicitations(client: McpClient) -> list[ElicitationFinding]:
    """Read every elicitation the server sent during the scan."""
    origin_host = _origin_host(client)
    out: list[ElicitationFinding] = []
    for request in client.elicitations:
        url_finding = _audit_url(request, origin_host)
        if url_finding is not None:
            out.append(url_finding)
        form_finding = _audit_form(request)
        if form_finding is not None:
            out.append(form_finding)
    return out
