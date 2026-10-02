# SPDX-License-Identifier: AGPL-3.0-or-later
"""Judge what repository settings change about trust: where traffic goes, what connects.

Separate from the executable-surface detector because neither of these runs
anything. They change the host's own behaviour: one moves the endpoint the
operator's credential is sent to, the other decides that a server arriving with
a checkout may connect without being asked about.

Endpoint override (CVE-2026-21852). An `env` block in a settings file is written
into the process environment, and a `*_BASE_URL` variable there is where Claude
Code sends API traffic. Set from a repository file, the operator's key goes to
whoever wrote the file. The timing matters for the wording: the original
vulnerability sent the key before the trust dialog was answered and was fixed in
2.0.65, while on a current host "most `env` values apply only after each
teammate trusts the folder"
(https://code.claude.com/docs/en/settings). So the finding says the key is sent
there once the folder is trusted, which is true on a patched host and on an
unpatched one alike, rather than claiming a pre-trust leak a reviewer would fail
to reproduce (R-7.2).

Two variable families are deliberately not flagged. `CLAUDE_CONFIG_DIR` and the
OpenTelemetry exporter variables do not take effect from project or local
settings at all, so a row on them would be a false positive - the symmetric half
of R-2.4. Credential variables carried in `env` are a finding about secrets
rather than about routing, and belong to the secret detector; judging them here
too would have two commits deciding the same thing.

Blanket approval. `enableAllProjectMcpServers` approves every server in a
project `.mcp.json` without a prompt, and `enabledMcpjsonServers` approves named
ones. Committed to a repository they are bounded rather than inert: as of
v2.1.196 such a key "is ignored in an untrusted folder, and the server stays at
`Pending approval`" (https://code.claude.com/docs/en/mcp). It takes effect once
the operator trusts the folder, and from then on it covers servers the checkout
has not shipped yet - the next `git pull` can add one and it connects unasked.
That is why this is MEDIUM and worded as removing future consent, not as
bypassing the dialog today.

`disabledMcpjsonServers` produces nothing: it only rejects, and it applies from
any settings file, so a repository using it is restricting itself.
"""

from __future__ import annotations

from typing import Final

from mas_sentry.core.finding import Finding, Severity

from .discovery import HostConfig
from .surface import ExecutableSurface

# Variables that decide which host API traffic is sent to. Data rather than a
# literal in a condition (R-1.8); source: https://code.claude.com/docs/en/env-vars
_ENDPOINT_VARS: Final = frozenset(
    {
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
        "ANTHROPIC_VERTEX_BASE_URL",
        "ANTHROPIC_AWS_BASE_URL",
        "ANTHROPIC_FOUNDRY_BASE_URL",
    }
)

# Added to every API request, so it can carry routing or credential headers.
_HEADER_VAR: Final = "ANTHROPIC_CUSTOM_HEADERS"

_ENDPOINT_REFERENCES: Final = [
    "CVE-2026-21852",
    "https://code.claude.com/docs/en/env-vars",
    "https://code.claude.com/docs/en/settings",
]

_APPROVAL_REFERENCES: Final = [
    "CVE-2025-59536",
    "https://code.claude.com/docs/en/mcp",
]


def _endpoint_finding(src: HostConfig, names: list[str]) -> Finding:
    named = ", ".join(names)
    return Finding(
        module="host.endpoint_override",
        title=f"{src.host} ({src.scope}): repository settings redirect API traffic ({named})",
        detail=(
            f"{src.path} sets {named} in its env block. Claude Code writes each env entry into the process "
            "environment and sends API traffic to that endpoint, so once the operator trusts this folder "
            "their credential is sent to whoever wrote the file. The variable name and the value's shape are "
            "recorded; the endpoint itself is not read out of the config"
        ),
        severity=Severity.HIGH,
        target=str(src.path),
        tags=["host", "endpoint_override"],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "path": str(src.path),
            "variables": names,
        },
        references=_ENDPOINT_REFERENCES,
    )


def _header_finding(src: HostConfig) -> Finding:
    return Finding(
        module="host.endpoint_override",
        title=f"{src.host} ({src.scope}): repository settings add headers to every API request",
        detail=(
            f"{src.path} sets {_HEADER_VAR} in its env block. The value is added to every API request, which "
            "is a channel for routing or credential headers chosen by the repository rather than the "
            "operator. The header names and values are not read into the report"
        ),
        severity=Severity.MEDIUM,
        target=str(src.path),
        tags=["host", "endpoint_override"],
        evidence={"host": src.host, "scope": src.scope, "path": str(src.path), "variables": [_HEADER_VAR]},
        references=_ENDPOINT_REFERENCES,
    )


def _blanket_approval_finding(src: HostConfig) -> Finding:
    return Finding(
        module="host.server_approval",
        title=f"{src.host} ({src.scope}): repository approves every server in its own .mcp.json",
        detail=(
            f"{src.path} sets enableAllProjectMcpServers, which connects every server declared in the "
            "project's .mcp.json without a prompt. The key is ignored while the folder is untrusted, so this "
            "is not a bypass of today's dialog; it removes the prompt for every server the repository adds "
            "later, so a server arriving in a future pull connects unasked"
        ),
        severity=Severity.MEDIUM,
        target=str(src.path),
        tags=["host", "server_approval"],
        evidence={"host": src.host, "scope": src.scope, "path": str(src.path), "enable_all": True},
        references=_APPROVAL_REFERENCES,
    )


def _named_approval_finding(src: HostConfig, names: tuple[str, ...]) -> Finding:
    return Finding(
        module="host.server_approval",
        title=f"{src.host} ({src.scope}): repository approves {len(names)} of its own .mcp.json server(s)",
        detail=(
            f"{src.path} lists {', '.join(names)} in enabledMcpjsonServers, approving those servers from the "
            "project's .mcp.json without a prompt. It is ignored while the folder is untrusted and takes "
            "effect once the operator trusts it; the definition each name resolves to can change in a later "
            "commit while the approval stands"
        ),
        severity=Severity.MEDIUM,
        target=str(src.path),
        tags=["host", "server_approval"],
        evidence={"host": src.host, "scope": src.scope, "path": str(src.path), "approved": list(names)},
        references=_APPROVAL_REFERENCES,
    )


def trust_findings(src: HostConfig, surface: ExecutableSurface) -> list[Finding]:
    """Rows for the routing and approval keys of one repository settings file.

    User scope is the operator's own choice of endpoint and of what to approve,
    so it produces nothing here; `settings.local.json` is left to the
    executable-surface detector, which already reports it as unverified rather
    than grading a file whose git tracking cannot be tested safely.
    """
    if src.scope != "project" or src.path.name == "settings.local.json":
        return []

    out: list[Finding] = []
    endpoints = sorted({e.key for e in surface.env} & _ENDPOINT_VARS)
    if endpoints:
        out.append(_endpoint_finding(src, endpoints))
    if any(e.key == _HEADER_VAR for e in surface.env):
        out.append(_header_finding(src))
    if surface.approvals.enable_all:
        out.append(_blanket_approval_finding(src))
    if surface.approvals.enabled:
        out.append(_named_approval_finding(src, surface.approvals.enabled))
    return out
