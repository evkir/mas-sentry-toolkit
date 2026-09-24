# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit a discovered A2A AgentCard for security-relevant configuration.

Only properties an AgentCard can actually express are checked here. Two
earlier checks read fields that exist in no A2A generation - a rate-limit
declaration under capabilities, and a webhook signing scheme under
authentication - so they fired on every card advertising streaming or push
notifications and could not be cleared by any real agent. Rate limiting is
simply not card-expressible, and push-callback authentication is negotiated
per task in TaskPushNotificationConfig.authentication at runtime rather than
declared up front, so neither has a card-side replacement. A check that
cannot distinguish a secure agent from an insecure one is noise regardless
of how sound its motivating threat is.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from mas_sentry.core.injection_scan import scan_routing_hijack, scan_string

from .client import AgentCard

# AgentCard skill counts above this threshold are flagged for review.
LARGE_SKILL_THRESHOLD = 20

# Four-lens taxonomy for Agent Card Poisoning: injection directives embedded in
# card metadata that hijack an orchestrator's LLM-based task routing. Same
# directive class MAS-Sentry detects in MCP tool descriptors and agent traffic.
_POISONING_TAGS = ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"]
# Routing-hijack: persuasive selection-steering (no classic injection token).
# Same goal-hijack taxonomy family as poisoning; a distinct, lower-severity signature.
_ROUTING_HIJACK_TAGS = ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"]
# Cleartext card endpoint enables card tampering / impersonation in transit.
_CLEARTEXT_TAGS = ["CWE-319", "STRIDE_Tampering"]

# Four-lens taxonomy for the structural card findings, so every A2A card
# finding - not only poisoning/transport - carries ASI/CWE/STRIDE for
# consistent SARIF ranking and cross-taxonomy filtering.
# Missing / anonymous auth -> anyone can act as a client (impersonation).
_MISSING_AUTH_TAGS = ["ASI03_Identity_Abuse", "CWE-306", "STRIDE_Spoofing"]
# Excessive advertised skill surface -> least-privilege violation, broader
# abuse paths. Softest of the set; kept LOW and tagged honestly, not padded.
_SKILL_SURFACE_TAGS = ["ASI02_Tool_Misuse", "CWE-272", "STRIDE_Elevation_Of_Privilege"]
# Absent card signature -> client cannot verify origin or detect tampering.
_UNSIGNED_CARD_TAGS = ["ASI03_Identity_Abuse", "CWE-347", "STRIDE_Spoofing"]
# A declared signature whose header cannot carry verification -> same spoofing
# outcome as no signature at all, so the same ASI/STRIDE pair with CWE-347.
_SIG_UNVERIFIABLE_TAGS = ["ASI03_Identity_Abuse", "CWE-347", "STRIDE_Spoofing"]
# Algorithm that cannot prove origin to a third party (symmetric or unknown).
_SIG_ALG_TAGS = ["ASI03_Identity_Abuse", "CWE-327", "STRIDE_Spoofing"]
# jku points a verifier at a key source outside the card's own origin.
_SIG_JKU_TAGS = ["ASI03_Identity_Abuse", "CWE-346", "STRIDE_Spoofing"]

# Algorithms that let a party holding only the public key verify the card.
# A symmetric alg (HS*) is deliberately absent: verifying an HS signature
# requires the same secret that produced it, so a publicly fetched card signed
# that way proves origin to nobody who did not already share the key.
_ASYMMETRIC_ALGS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES256K",
        "ES384",
        "ES512",
        "EdDSA",
        "Ed25519",
        "Ed448",
    }
)
# Only this many signature entries are inspected. A card is attacker-supplied
# input; without a bound, a hostile card carrying thousands of malformed
# entries turns one audit into thousands of report rows.
_MAX_SIGNATURES_INSPECTED = 8
# Header values are echoed back into the report, so they are truncated to a
# window rather than relayed whole.
_SIG_VALUE_WINDOW = 32
# Sole declared scheme type is a bare API key -> weakest of the five v1.0
# scheme types, no built-in rotation/expiry, no stronger alternative offered.
_WEAK_SCHEME_TAGS = ["ASI03_Identity_Abuse", "CWE-798", "STRIDE_Spoofing"]
# OAuth2 scope names that grant sweeping authority. Coarse-grained token
# scopes are the concrete cross-agent privilege-escalation vector named across
# the 2026 A2A threat literature: an agent granted an admin-family scope holds
# far more privilege than any one skill needs. Matched case-insensitively against
# the exact scope name (substring matches would false-positive on e.g. wallet).
_BROAD_SCOPE_LITERALS = frozenset(
    {"all", "admin", "administrator", "superuser", "root", "owner", "full", "full_access"}
)
# Overbroad scope grant -> agent holds more authority than needed. Repo taxonomy
# names ASI03 as Identity and Privilege Abuse; CWE-269 is Improper Privilege
# Management. No clean verified ATLAS technique, so left untagged.
_BROAD_SCOPE_TAGS = ["ASI03_Identity_Abuse", "CWE-269", "STRIDE_Elevation_Of_Privilege"]

# v1.0's SecurityScheme is a proto oneof; per the v1.0 spec ("the field name
# itself serves as the type discriminator") the canonical JSON shape carries
# the type as a member key on the scheme object. Real-world examples from
# multiple A2A tooling vendors instead show an OpenAPI-style "type" string
# (SecurityScheme is explicitly "based on the OpenAPI 3.2 Security Scheme
# Object", and OpenAPI's own convention is a type field) - both are checked
# rather than betting on one until the ecosystem converges on one shape.
_SCHEME_MEMBER_KEYS = {
    "apiKeySecurityScheme": "apiKey",
    "httpAuthSecurityScheme": "http",
    "oauth2SecurityScheme": "oauth2",
    "openIdConnectSecurityScheme": "openIdConnect",
    "mtlsSecurityScheme": "mtls",
}
# A card declares which schemes are actually mandatory under a different key
# per generation: v1.0 named it securityRequirements (a2a.proto field 9),
# v0.3.x named it security. Both are checked, because reading only the v1.0
# spelling reports a fully secured legacy card as having no auth at all.
_REQUIREMENT_KEYS = ("securityRequirements", "security")

_SCHEME_TYPE_ALIASES = {"mutualtls": "mtls", "mutualTLS": "mtls", "mtls": "mtls"}


@dataclass(frozen=True, slots=True)
class CardFinding:
    severity: str
    title: str
    detail: str
    tags: list[str] = field(default_factory=list)


def audit_agent_card(card: AgentCard) -> list[CardFinding]:
    out: list[CardFinding] = []

    out.extend(_check_no_auth(card))
    out.extend(_check_weak_scheme_only(card))
    out.extend(_check_overbroad_scopes(card))

    if len(card.skills) > LARGE_SKILL_THRESHOLD:
        out.append(
            CardFinding(
                severity="LOW",
                title=f"Agent advertises {len(card.skills)} skills",
                detail=("Large skill surface increases attack surface; review for unused skills"),
                tags=_SKILL_SURFACE_TAGS,
            )
        )

    out.extend(_check_signature_absence(card))
    out.extend(_check_signature_headers(card))
    out.extend(_scan_card_poisoning(card))
    out.extend(_scan_routing_hijack(card))
    out.extend(_check_insecure_transport(card))

    return out


def _check_signature_absence(card: AgentCard) -> list[CardFinding]:
    """Flag an AgentCard published without a JWS signature (A2A v1.0 AgentCardSignature).

    Signing is optional per spec ("MAY"), but v1.0 defines it as the mechanism
    that lets a client verify a card originates from the claimed provider and
    was not tampered with (RFC 7515 JWS over RFC 8785 canonicalized content).
    An unsigned card cannot be distinguished from a spoofed or on-path-modified
    one, so absence is itself a passive finding.
    """
    if not card.raw.get("signatures"):
        return [
            CardFinding(
                severity="MEDIUM",
                title="AgentCard is not signed",
                detail=(
                    "No signatures[] field present; a client has no way to verify this "
                    "card originates from the claimed provider or was not tampered with "
                    "in transit (A2A v1.0 AgentCardSignature, RFC 7515 JWS)"
                ),
                tags=list(_UNSIGNED_CARD_TAGS),
            )
        ]
    return []


def _decode_protected(value: object) -> dict | None:
    """Decode a signature's base64url `protected` header into its JSON object.

    Returns None when the field is absent, is not a string, does not decode as
    base64url, or does not decode to a JSON object. The caller reports that as
    a malformed entry rather than guessing what the publisher meant.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _window(value: object) -> str:
    """Render an untrusted header value, truncated to a fixed window."""
    text = str(value)
    if len(text) > _SIG_VALUE_WINDOW:
        return text[:_SIG_VALUE_WINDOW] + "..."
    return text


def _check_signature_headers(card: AgentCard) -> list[CardFinding]:
    """Audit the JWS protected header of each AgentCardSignature on the card.

    A2A v1.0 (spec section 8.4.2) defines signatures[] as RFC 7515 JWS over the
    RFC 8785 canonical card. Until this check existed the audit asked only
    whether signatures[] was non-empty, so a card declaring alg=none - or
    pointing its verifier at a key set on a domain the publisher does not
    control - passed as signed. That reading is worse than no check: a spoofed
    card scored better than an honest unsigned one.

    This is a header audit, not a verification. No key is fetched (a jku is
    reported, never requested - the same outbound-request class closed for
    MCP auth metadata), the signature bytes are not checked against any key,
    and the JCS canonicalization of the payload is not recomputed. A card with
    a flawless header over a garbage signature clears this check. Verifying
    requires the publisher's key and belongs to the client, not to a passive
    scan; the boundary is named here rather than implied.

    `typ` is deliberately not checked. The spec asks for "JOSE", but PyJWT -
    which the reference Python SDK signs through - stamps typ="JWT" whenever
    the caller does not set it explicitly, so flagging the absence of "JOSE"
    would fire on a conformant reference signature (verified by signing with
    the live library, not read off the spec).
    """
    signatures = card.raw.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        return []

    out: list[CardFinding] = []
    card_host = urlsplit((card.url or "").strip()).hostname
    for index, entry in enumerate(signatures[:_MAX_SIGNATURES_INSPECTED]):
        where = f"signatures[{index}]"
        header = _decode_protected(entry.get("protected")) if isinstance(entry, dict) else None
        if header is None:
            out.append(
                CardFinding(
                    severity="LOW",
                    title=f"AgentCard {where} carries no decodable protected header",
                    detail=(
                        "The protected member is absent, is not a base64url string, or does not "
                        "decode to a JSON object; no client can determine how this card was signed "
                        "(A2A v1.0 section 8.4.2, RFC 7515)"
                    ),
                    tags=list(_SIG_UNVERIFIABLE_TAGS),
                )
            )
            continue
        out.extend(_check_signature_alg(header, where))
        out.extend(_check_signature_kid(header, where))
        out.extend(_check_signature_jku(header, where, card_host))
    return out


def _check_signature_alg(header: dict, where: str) -> list[CardFinding]:
    """Report a signing algorithm that cannot establish the card's origin."""
    alg = header.get("alg")
    if not isinstance(alg, str) or not alg.strip():
        return [
            CardFinding(
                severity="HIGH",
                title=f"AgentCard {where} omits the signing algorithm",
                detail=(
                    "The protected header carries no alg, which RFC 7515 requires; the signature "
                    "cannot be verified and the card's claimed origin rests on nothing"
                ),
                tags=list(_SIG_UNVERIFIABLE_TAGS),
            )
        ]
    if alg.strip().lower() == "none":
        return [
            CardFinding(
                severity="HIGH",
                title=f"AgentCard {where} declares alg=none",
                detail=(
                    "The card advertises a signature computed with no algorithm, so the signature "
                    "value proves nothing; any party can republish this card under the claimed "
                    "provider's name and it still presents as signed"
                ),
                tags=list(_SIG_UNVERIFIABLE_TAGS),
            )
        ]
    if alg not in _ASYMMETRIC_ALGS:
        return [
            CardFinding(
                severity="MEDIUM",
                title=f"AgentCard {where} signed with a non-verifiable algorithm",
                detail=(
                    f"alg={_window(alg)} is not one of the asymmetric algorithms a third party can "
                    "verify from a public key; a symmetric or unrecognized algorithm on a publicly "
                    "fetched card cannot prove the card came from its claimed provider"
                ),
                tags=list(_SIG_ALG_TAGS),
            )
        ]
    return []


def _check_signature_kid(header: dict, where: str) -> list[CardFinding]:
    """Report a protected header with no key identifier."""
    kid = header.get("kid")
    if isinstance(kid, str) and kid.strip():
        return []
    return [
        CardFinding(
            severity="LOW",
            title=f"AgentCard {where} carries no key identifier",
            detail=(
                "kid is absent from the protected header, so a verifier holding more than one "
                "publisher key cannot tell which one to use; A2A v1.0 requires it and the "
                "reference SDK's ProtectedHeader type does too"
            ),
            tags=list(_SIG_UNVERIFIABLE_TAGS),
        )
    ]


def _check_signature_jku(header: dict, where: str, card_host: str | None) -> list[CardFinding]:
    """Report a jku that sends the verifier somewhere other than the card's origin.

    The jku is reported, never fetched. Resolving it is an outbound request to
    an address the target chose, which is the request class this scanner does
    not make on a target's say-so.
    """
    jku = header.get("jku")
    if not isinstance(jku, str) or not jku.strip():
        return []
    parts = urlsplit(jku.strip())
    out: list[CardFinding] = []
    if parts.scheme.lower() != "https":
        out.append(
            CardFinding(
                severity="MEDIUM",
                title=f"AgentCard {where} points jku at a non-HTTPS key set",
                detail=(
                    f"jku scheme is {_window(parts.scheme or '(none)')}; a verifier following it "
                    "fetches the signing keys over a channel an on-path attacker can rewrite, "
                    "which defeats the signature it was about to check"
                ),
                tags=list(_SIG_JKU_TAGS),
            )
        )
    jku_host = parts.hostname
    if card_host and jku_host and jku_host.lower() != card_host.lower():
        out.append(
            CardFinding(
                severity="MEDIUM",
                title=f"AgentCard {where} points jku at another origin",
                detail=(
                    f"jku host {_window(jku_host)} differs from the card origin {_window(card_host)}; "
                    "a client that honours it verifies the card against keys published by whoever "
                    "controls that host, so tampering with the card only requires controlling it"
                ),
                tags=list(_SIG_JKU_TAGS),
            )
        )
    return out


def _check_no_auth(card: AgentCard) -> list[CardFinding]:
    """Flag an AgentCard that enforces no authentication requirement.

    Checks every card shape MST may see in a mixed real-world fleet (same
    rationale as the discovery fallback in client.py). Both current
    generations publish securitySchemes and then name the mandatory subset
    separately - securityRequirements in v1.0, security in v0.3.x - so both
    requirement keys are honoured. Reading only the v1.0 spelling reported a
    fully secured v0.3.x card as enforcing no authentication at all, a HIGH
    false positive on exactly the agents that got it right.

    A card carrying any of those keys is treated as current-shaped and the
    pre-0.3 fallback is skipped, so an agent is not double-flagged by a shape
    it no longer emits. Only when none of them is present does the fallback
    run, reading the authentication.schemes list that A2A used before 0.3
    moved to securitySchemes; that still resolves correctly for a genuinely
    auth-less card.
    """
    if "securitySchemes" in card.raw or any(key in card.raw for key in _REQUIREMENT_KEYS):
        if not any(card.raw.get(key) for key in _REQUIREMENT_KEYS):
            return [
                CardFinding(
                    severity="HIGH",
                    title="AgentCard enforces no authentication requirement",
                    detail=(
                        "No security requirement is declared (securityRequirements[] in v1.0, "
                        "security[] in v0.3.x), so no securitySchemes entry is actually required "
                        "to submit tasks - anyone can act as a client"
                    ),
                    tags=_MISSING_AUTH_TAGS,
                )
            ]
        return []

    auth = card.authentication or {}
    schemes = auth.get("schemes") or []
    if not schemes:
        return [
            CardFinding(
                severity="HIGH",
                title="AgentCard declares no authentication schemes",
                detail="Anyone can submit tasks to this agent",
                tags=_MISSING_AUTH_TAGS,
            )
        ]
    if "none" in [str(s).lower() for s in schemes]:
        return [
            CardFinding(
                severity="HIGH",
                title="AgentCard explicitly allows scheme 'none'",
                detail="Anonymous access enabled",
                tags=_MISSING_AUTH_TAGS,
            )
        ]
    return []


def _scheme_kind(scheme: object) -> str | None:
    """Resolve a securitySchemes entry to its type, or None if unrecognized."""
    if not isinstance(scheme, dict):
        return None
    for member_key, kind in _SCHEME_MEMBER_KEYS.items():
        if member_key in scheme:
            return kind
    type_field = scheme.get("type")
    if isinstance(type_field, str):
        normalized = _SCHEME_TYPE_ALIASES.get(type_field, type_field)
        if normalized in _SCHEME_MEMBER_KEYS.values():
            return normalized
    return None


def _check_weak_scheme_only(card: AgentCard) -> list[CardFinding]:
    """Flag a v1.0 card whose only recognized scheme type is a bare API key.

    An API key alone carries no rotation or expiry semantics and is the
    weakest of the five v1.0 scheme types (apiKey/http/oauth2/openIdConnect/
    mtls). Does not fire on legacy v0.3.x cards - authentication.schemes
    strings do not carry enough structure to distinguish an API key from
    anything else - nor on a card with zero schemes at all, which is
    _check_no_auth's finding, not this one's.
    """
    schemes = card.raw.get("securitySchemes")
    if not isinstance(schemes, dict) or not schemes:
        return []
    kinds = {_scheme_kind(s) for s in schemes.values()}
    kinds.discard(None)
    if kinds == {"apiKey"}:
        return [
            CardFinding(
                severity="LOW",
                title="AgentCard's only authentication scheme is a bare API key",
                detail=(
                    "No oauth2/http/openIdConnect/mtls scheme is offered as an "
                    "alternative; a static key has no built-in rotation or "
                    "expiry and is the weakest of the five v1.0 scheme types - "
                    "consider offering a stronger option"
                ),
                tags=_WEAK_SCHEME_TAGS,
            )
        ]
    return []


def _oauth2_flows(scheme: object) -> dict:
    """Return the flows mapping of an oauth2 scheme across both card shapes."""
    if not isinstance(scheme, dict):
        return {}
    member = scheme.get("oauth2SecurityScheme")
    if isinstance(member, dict):
        flows = member.get("flows")
        return flows if isinstance(flows, dict) else {}
    if scheme.get("type") == "oauth2":
        flows = scheme.get("flows")
        return flows if isinstance(flows, dict) else {}
    return {}


def _collect_scope_names(flows: dict) -> set[str]:
    """Collect scope names across every flow, tolerating dict or list scopes."""
    names: set[str] = set()
    for flow in flows.values():
        if not isinstance(flow, dict):
            continue
        scopes = flow.get("scopes")
        if isinstance(scopes, dict):
            names.update(str(k) for k in scopes)
        elif isinstance(scopes, list):
            names.update(str(x) for x in scopes)
    return names


def _check_overbroad_scopes(card: AgentCard) -> list[CardFinding]:
    """Flag OAuth2 schemes advertising sweeping (wildcard / admin-family) scopes.

    Coarse-grained token scopes are the concrete privilege-escalation vector named
    across the 2026 A2A threat literature: an agent granted a wildcard or an
    admin-family scope holds far more authority than any one skill needs, so a
    compromised or malicious peer can escalate across the delegation boundary.
    Scope names are free-form, so this is review-framed and split by confidence:
    a wildcard is coarse by definition (MEDIUM); an admin-family literal is a
    naming convention, not a guarantee (LOW). Exact offending scopes are listed
    rather than asserting exploitability.
    """
    schemes = card.raw.get("securitySchemes")
    if not isinstance(schemes, dict) or not schemes:
        return []
    wildcard: set[str] = set()
    literal: set[str] = set()
    for scheme in schemes.values():
        for name in _collect_scope_names(_oauth2_flows(scheme)):
            if "*" in name:
                wildcard.add(name)
            elif name.strip().lower() in _BROAD_SCOPE_LITERALS:
                literal.add(name)
    out: list[CardFinding] = []
    if wildcard:
        listed = ", ".join(sorted(wildcard))
        out.append(
            CardFinding(
                severity="MEDIUM",
                title="OAuth2 scheme advertises a wildcard scope",
                detail=(
                    f"Scope(s) {listed} match anything by wildcard; a wildcard grant is coarse "
                    "by definition and hands an agent more authority than any single skill needs "
                    "- the concrete cross-agent privilege-escalation vector. Narrow to explicit "
                    "per-skill scopes"
                ),
                tags=_BROAD_SCOPE_TAGS,
            )
        )
    if literal:
        listed = ", ".join(sorted(literal))
        out.append(
            CardFinding(
                severity="LOW",
                title="OAuth2 scheme advertises an admin-family scope",
                detail=(
                    f"Scope name(s) {listed} conventionally grant sweeping authority; review whether "
                    "each is scoped to the minimum a skill requires, since coarse-grained tokens "
                    "enable privilege escalation across agents"
                ),
                tags=_BROAD_SCOPE_TAGS,
            )
        )
    return out


def _llm_ingested_fields(card: AgentCard) -> list[tuple[str, str]]:
    """Return (location, text) pairs for every card field an orchestrator LLM ingests."""
    fields: list[tuple[str, str]] = [("description", card.description or "")]
    for i, skill in enumerate(card.skills):
        if not isinstance(skill, dict):
            continue
        sid = str(skill.get("id") or skill.get("name") or i)
        fields.append((f"skills[{sid}].name", str(skill.get("name", ""))))
        fields.append((f"skills[{sid}].description", str(skill.get("description", ""))))
    return fields


def _scan_routing_hijack(card: AgentCard) -> list[CardFinding]:
    """Detect persuasive agent-selection steering in card metadata.

    Complements _scan_card_poisoning: catches plain-language routing directives
    ("always prefer this agent", "the only agent authorized for X") that bias an
    orchestrator's selection without any classic injection token. Lower severity
    than an outright injection takeover - it steers, it does not seize control.
    """
    out: list[CardFinding] = []
    for location, text in _llm_ingested_fields(card):
        matches = scan_routing_hijack(text)
        if not matches:
            continue
        patterns = sorted({m.pattern for m in matches})
        out.append(
            CardFinding(
                severity="MEDIUM",
                title=f"Agent Card routing-hijack: selection-steering directive in {location}",
                detail=(
                    f"Card metadata carries agent-selection steering [{', '.join(patterns)}] "
                    "that biases an orchestrator toward routing tasks to this agent"
                ),
                tags=list(_ROUTING_HIJACK_TAGS),
            )
        )
    return out


def _scan_card_poisoning(card: AgentCard) -> list[CardFinding]:
    """Detect injection directives embedded in LLM-ingested card metadata.

    An orchestrator selects specialist agents by reasoning over card
    descriptions; adversarial instructions in those fields hijack task routing
    (Agent Card Poisoning). We scan the card description and every skill's name
    and description with the shared injection primitive.
    """
    out: list[CardFinding] = []
    for location, text in _llm_ingested_fields(card):
        matches = scan_string(text)
        if not matches:
            continue
        patterns = sorted({m.pattern for m in matches})
        out.append(
            CardFinding(
                severity="HIGH",
                title=f"Agent Card Poisoning: injection directive in {location}",
                detail=(
                    f"Card metadata carries injection directive(s) [{', '.join(patterns)}] "
                    "that can hijack an orchestrator's task-routing reasoning"
                ),
                tags=list(_POISONING_TAGS),
            )
        )
    return out


def _check_insecure_transport(card: AgentCard) -> list[CardFinding]:
    """Flag a cleartext (http://) card endpoint - it invites card tampering."""
    url = (card.url or "").strip().lower()
    if url.startswith("http://"):
        return [
            CardFinding(
                severity="MEDIUM",
                title="AgentCard endpoint served over cleartext HTTP",
                detail=("Card and task traffic are unencrypted; an on-path attacker can tamper the card or messages"),
                tags=list(_CLEARTEXT_TAGS),
            )
        ]
    return []
