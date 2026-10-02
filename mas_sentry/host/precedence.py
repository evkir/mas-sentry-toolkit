# SPDX-License-Identifier: AGPL-3.0-or-later
"""Flag a repository server that takes over a name the operator configured.

Every other host finding is a property of one file. This one is a property of a
pair, which is why it gets its own pass over the whole set rather than another
branch inside the per-file loop (R-1.7).

The mechanism is name precedence. Claude Code resolves a server that several
scopes declare by taking one definition whole:

    "When the same server is defined in more than one place, Claude Code
    connects to it once, using the definition from the highest-precedence
    source. The entire server entry from that source is used; fields are not
    merged across scopes."
    -- https://code.claude.com/docs/en/mcp

The order is local, then project, then user. So a `.mcp.json` arriving with a
checkout outranks the operator's own user-scope entry: the name the operator
trusted keeps working, and something else runs behind it. Nothing is merged, so
the replacement's `command`, `args` and `env` are the ones that take effect -
the operator's are simply not consulted.

Two things bound the verdict, and both are stated in the finding rather than
assumed away:

- Local scope outranks project scope, and local servers live under `projects`
  in `~/.claude.json`, which this reader does not descend into. A local entry
  for the same name would win over both sides reported here. When that key went
  unread, the finding says the comparison covers project against user only.
- Precedence is defined within one host. The portable `.mcp.json` is read by
  more than one host, so pairing it with a user-scope file is sound, but this
  module does not assert which host reads which file beyond what discovery
  states: both paths go into the evidence and the reviewer sees the pair.

A project entry whose definition is identical to the user one raises nothing. It
takes precedence too, but it launches what the operator already configured, and
a row on every repository that ships the same server definition as its
developers' machines would be noise (R-2.4).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from mas_sentry.core.finding import Finding, Severity

from .inventory import Inventory, ServerEntry

# The key in `~/.claude.json` that holds local-scope, per-project servers. Local
# scope outranks project scope, so an unread one bounds this comparison.
_LOCAL_SCOPE_KEY: Final = "projects"

_REFERENCES: Final = [
    "CVE-2026-21852",
    "https://code.claude.com/docs/en/mcp",
]


@dataclass(frozen=True, slots=True)
class _Side:
    """One scope's definition of a server name, for both sides of the change."""

    inv: Inventory
    server: ServerEntry


def _launch(server: ServerEntry) -> tuple[Any, ...]:
    """The fields that decide what actually runs, in a comparable shape.

    `env` is included by key and form rather than value: swapping which
    variables a launch receives changes the launch even when the command is
    untouched, and the values are not ours to hold (R-7.3).
    """
    return (
        server.declared_type,
        server.command,
        server.args,
        server.url,
        server.env_file,
        server.cwd,
        tuple(sorted((e.key, e.shape.form) for e in server.env)),
        server.header_names,
    )


def _side_evidence(side: _Side) -> dict[str, Any]:
    src = side.inv.source
    server = side.server
    return {
        "host": src.host,
        "scope": src.scope,
        "path": str(src.path),
        "declared_type": server.declared_type,
        "command": server.command,
        "args_count": len(server.args),
        "url": server.url,
        "cwd": server.cwd,
        "env_keys": [e.key for e in server.env],
        "env_forms": {e.key: e.shape.form for e in server.env},
        "env_file": server.env_file,
        "header_names": list(server.header_names),
    }


def _changed_fields(project: ServerEntry, user: ServerEntry) -> list[str]:
    """Name the launch fields that differ, so the row says what was swapped."""
    names = ("declared_type", "command", "args", "url", "env_file", "cwd", "env", "header_names")
    return [name for name, a, b in zip(names, _launch(project), _launch(user), strict=True) if a != b]


def _override_finding(project: _Side, user: _Side, *, local_unread: bool) -> Finding:
    name = project.server.name
    changed = ", ".join(_changed_fields(project.server, user.server))
    bound = (
        " Local scope outranks project scope and was not read, so this compares the project entry against "
        "the user one; a local entry for the same name would take precedence over both."
        if local_unread
        else ""
    )
    return Finding(
        module="host.server_override",
        title=f"{name}: repository config takes over a server the operator configured",
        detail=(
            f"'{name}' is declared in {user.inv.source.path} (user scope) and again in "
            f"{project.inv.source.path}, which arrives with a checkout. Project scope outranks user scope and "
            f"the entry is taken whole rather than merged, so the repository's definition is what runs and the "
            f"operator's is not consulted. These fields differ: {changed}. Both sides are in the evidence."
            f"{bound}"
        ),
        severity=Severity.HIGH,
        target=str(project.inv.source.path),
        tags=["host", "server_override"],
        evidence={
            "server": name,
            "changed_fields": _changed_fields(project.server, user.server),
            "wins": _side_evidence(project),
            "overridden": _side_evidence(user),
            "local_scope_unread": local_unread,
        },
        references=_REFERENCES,
    )


def cross_scope_findings(inventories: list[Inventory]) -> list[Finding]:
    """Compare project-scope server declarations against user-scope ones by name.

    Only a name declared in both scopes with a different definition produces a
    row. A name that appears once belongs to whichever scope declared it, and
    an identical redeclaration launches what the operator already had.
    """
    user_sides: dict[str, list[_Side]] = {}
    local_unread = False
    for inv in inventories:
        if inv.source.scope != "user":
            continue
        if _LOCAL_SCOPE_KEY in inv.unmodelled_top_level:
            local_unread = True
        for server in inv.servers:
            user_sides.setdefault(server.name, []).append(_Side(inv, server))

    out: list[Finding] = []
    for inv in inventories:
        if inv.source.scope != "project":
            continue
        for server in inv.servers:
            for user in user_sides.get(server.name, ()):
                if _launch(server) != _launch(user.server):
                    out.append(_override_finding(_Side(inv, server), user, local_unread=local_unread))
    return out
