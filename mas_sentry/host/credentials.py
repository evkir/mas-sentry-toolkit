# SPDX-License-Identifier: AGPL-3.0-or-later
"""Report a credential written into an agent config, without carrying it.

The reader labels a value against the documented credential formats
(`values.classify`). This module turns a label into a row. It never sees the
characters that earned the label, so the guarantee the whole operation rests on
is structural rather than a filter somebody has to remember to apply (R-7.3).

Scope decides how bad it is, not whether it is true. A literal key in a
repository file is in version control and in every clone, so it is HIGH and the
remedy is rotation, not deletion. The same key in a user-scope file is the
operator's own, sitting in plaintext on their disk: worth a row, not an
incident.

Three cases are deliberately silent, and each is a false positive the detector
would otherwise produce:

- `${VAR}` and `${input:api-key}`. A value that is entirely a placeholder holds
  no secret; the second form is the pattern the host offers precisely so a key
  is never written down. Firing on it would punish the config that did the right
  thing (R-2.4).
- A credential-named variable fed from the environment, such as
  `"GITHUB_TOKEN": "${GITHUB_TOKEN}"` in a repository `.mcp.json`. That is how a
  server is normally given a token, so a row on it would appear on most honest
  projects. Whether a repository should receive the operator's token at all is a
  question about the launch, which the precedence detector already covers when
  the repository takes over a name.
- A credential reference in a remote server's `url` or `headers`. The host reads
  covered credential variables there as empty rather than expanding them, so
  nothing is sent; a row would describe a leak that cannot happen.

What is reported instead of guessed: an `envFile` names a file this audit did
not open, so the secrets it carries are unassessed rather than absent, and that
is a stated gap (R-2.1).
"""

from __future__ import annotations

from typing import Final

from mas_sentry.core.finding import Finding, Severity

from .inventory import Inventory
from .values import CREDENTIAL_PREFIXES, EnvEntry

_REFERENCES: Final = [
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html",
]


def _format_name(label: str) -> str:
    """Render a label for a human: the issuer's name for a prefix, else the label."""
    if label.startswith("prefix:"):
        return CREDENTIAL_PREFIXES.get(label.removeprefix("prefix:"), label)
    return "JSON Web Token" if label == "jwt" else label


def _literal_finding(inv: Inventory, entry: EnvEntry, where: str) -> Finding:
    src = inv.source
    committed = src.scope == "project"
    kind = _format_name(entry.shape.credential or "")
    consequence = (
        "The file arrives with a checkout, so the value is in version control and in every clone: it needs "
        "rotating, not deleting"
        if committed
        else "The file is the operator's own, so this is a key kept in plaintext on disk rather than an "
        "exposure to anyone else"
    )
    return Finding(
        module="host.credential_literal",
        title=f"{src.host} ({src.scope}): {kind} written into {where} as {entry.key}",
        detail=(
            f"{src.path} carries a literal value in {where} under {entry.key}, and its form matches a "
            f"{kind}. {consequence}. The value itself is not read into this report - only the variable "
            f"name, the matched format and the length ({entry.shape.length} characters)"
        ),
        severity=Severity.HIGH if committed else Severity.MEDIUM,
        target=str(src.path),
        tags=["host", "credential_literal"],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "path": str(src.path),
            "where": where,
            "variable": entry.key,
            "credential_format": entry.shape.credential,
            "value_length": entry.shape.length,
        },
        references=_REFERENCES,
    )


def _env_file_finding(inv: Inventory, server: str, env_file: str) -> Finding:
    src = inv.source
    return Finding(
        module="host.credential_unread",
        title=f"{src.host} ({src.scope}): {server} loads its environment from a file this audit did not open",
        detail=(
            f"{src.path} points {server} at an envFile, so whatever credentials that file carries were not "
            "assessed. The path is recorded; the file was not read, because it sits outside the documented "
            "config set this audit covers. This row is a gap, not a clean result"
        ),
        severity=Severity.INFO,
        target=str(src.path),
        tags=["host", "credential_unread"],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "path": str(src.path),
            "server": server,
            "env_file": env_file,
        },
        references=_REFERENCES,
    )


def credential_findings(inv: Inventory) -> list[Finding]:
    """Rows for the literal credentials one config declares, and for what it hides.

    A server's `env` and a settings file's `env` are the same question asked of
    two schemas, so both are walked here rather than in two detectors.
    """
    out: list[Finding] = []
    for server in inv.servers:
        for entry in server.env:
            if entry.shape.credential is not None:
                out.append(_literal_finding(inv, entry, f"server '{server.name}' env"))
        if server.env_file is not None:
            out.append(_env_file_finding(inv, server.name, server.env_file))
    if inv.surface is not None:
        for entry in inv.surface.env:
            if entry.shape.credential is not None:
                out.append(_literal_finding(inv, entry, "the settings env block"))
    return out
