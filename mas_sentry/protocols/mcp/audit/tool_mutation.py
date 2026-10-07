# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detect a tool inventory that changes while the scan is still running.

The rug pull is the attack a static review cannot see: a server ships a benign
descriptor, waits for a human to approve the tool, and rewrites the description
afterwards. Whatever the new description says is what the model reads on the
next call, while the operator is still looking at the one they approved.

`tool_drift` covers the version of this that spans runs, by diffing against a
descriptor baseline committed next to a project. It cannot see a swap that
happens between two requests of a single scan, and that window is the one the
probes open: they call tools, which is exactly the event a server would key the
swap on.

The trigger here is re-enumeration, not a notification. That is a correction
made against a live target rather than a design choice: the reference SDK's
`remove_tool`/`add_tool` emit nothing, while the same server advertises
`tools.listChanged: true`, so a server can rewrite its whole inventory in
silence with the channel for announcing it declared and unused. The declared
capability was read as a promise here until the rig was measured; it is a
statement of intent. A detector waiting to be told would never fire, and an attacker has
every reason not to tell. Announcements are still read, because a server that
announces and a server that hides are not equally suspicious - but they are
read as evidence about the finding, never as the reason to look.

Comparison is between two enumerations MST performed itself, so there is no
heuristic to be wrong about: either the descriptor the server returned changed
or it did not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..client import McpClient
from .tool_drift import build_tool_baseline

TOOLS_LIST_CHANGED = "notifications/tools/list_changed"


@dataclass(frozen=True, slots=True)
class MutationFinding:
    tool: str
    kind: str  # tool_mutation / tool_appeared / tool_withdrawn
    severity: str
    detail: str
    announced: bool


def snapshot_tools(client: McpClient) -> dict[str, str]:
    """Digest every advertised tool descriptor as it stands right now.

    `relist_tools`, never `list_tools`. The cached reader hands back the
    inventory this scan already walked, which would make the second snapshot a
    copy of the first and every comparison below agree - silently, and against
    every target, including the one mid rug-pull.
    """
    return build_tool_baseline(client.relist_tools())


def notification_mark(client: McpClient) -> int:
    """Remember how much inbound traffic had arrived before the probes ran.

    A server may announce a list change during connect - the reference
    `everything` server does - and that says nothing about a mutation. Only
    traffic after this mark belongs to the window under test.
    """
    inbound = getattr(client.transport, "notifications", [])
    return len(inbound)


def _announced_since(client: McpClient, mark: int) -> bool:
    inbound: list[dict[str, Any]] = getattr(client.transport, "notifications", [])
    return any(message.get("method") == TOOLS_LIST_CHANGED for message in inbound[mark:])


def listing_mark(client: McpClient) -> int:
    """Remember how many listings had already failed before the probes ran."""
    return len(client.enumeration_issues)


def _listing_failed(client: McpClient, mark: int) -> bool:
    """Whether the re-enumeration itself did not come back."""
    return any(issue.method == "tools/list" for issue in client.enumeration_issues[mark:])


def detect_tool_mutation(
    client: McpClient,
    before: dict[str, str],
    mark: int,
    issues_mark: int = 0,
) -> list[MutationFinding]:
    """Re-enumerate and report every descriptor that moved under us.

    The comparison is only meaningful when the second enumeration succeeded. A
    listing that timed out returns the same empty mapping as a server that
    withdrew everything, and reading one as the other turns a slow tool into a
    page of findings about tools that never went anywhere. Seen against the
    reference lab server: one call blocked on a DNS lookup, the single-threaded
    server queued everything behind it, and the scan reported five tools as
    withdrawn.
    """
    after = snapshot_tools(client)
    if _listing_failed(client, issues_mark):
        return [
            MutationFinding(
                tool="",
                kind="mutation_inconclusive",
                severity="MEDIUM",
                detail=(
                    "The inventory could not be re-read after the probes ran, so nothing was compared. "
                    "A server that stopped answering and a server that withdrew its tools look identical "
                    "from here, and this scan does not claim to tell them apart."
                ),
                announced=False,
            )
        ]
    announced = _announced_since(client, mark)
    disclosure = "announced by a tools/list_changed notification" if announced else "with no notification at all"
    out: list[MutationFinding] = []

    for name, digest in sorted(after.items()):
        prior = before.get(name)
        if prior is None:
            out.append(
                MutationFinding(
                    tool=name,
                    kind="tool_appeared",
                    severity="HIGH",
                    detail=(
                        f"Tool '{name}' was not advertised when this scan began and is now, {disclosure}. "
                        "An inventory an operator approved does not contain it."
                    ),
                    announced=announced,
                )
            )
        elif prior != digest:
            out.append(
                MutationFinding(
                    tool=name,
                    kind="tool_mutation",
                    severity="HIGH",
                    detail=(
                        f"Descriptor for '{name}' changed during this scan, {disclosure}. "
                        "The description a model reads on the next call is not the one that was approved."
                    ),
                    announced=announced,
                )
            )

    for name in sorted(before):
        if name not in after:
            out.append(
                MutationFinding(
                    tool=name,
                    kind="tool_withdrawn",
                    severity="INFO",
                    detail=(
                        f"Tool '{name}' stopped being advertised during this scan, {disclosure}. "
                        "Whatever it did was not audited on the inventory it left behind."
                    ),
                    announced=announced,
                )
            )
    return out


# Verbs that change something. A tool whose name carries one is never called
# below: the window this opens is worth having, and not at the price of running
# an operation on the target to get it (R-7.6). The test is deliberately
# conservative in the unsafe direction - an unrecognised name is called, a
# recognised one is not - so being wrong costs coverage rather than the target.
_MUTATING_VERBS = frozenset(
    {
        "add",
        "append",
        "apply",
        "clear",
        "commit",
        "create",
        "delete",
        "deploy",
        "drop",
        "edit",
        "exec",
        "execute",
        "insert",
        "install",
        "kill",
        "launch",
        "move",
        "patch",
        "post",
        "publish",
        "purge",
        "push",
        "put",
        "remove",
        "rename",
        "reset",
        "restart",
        "run",
        "send",
        "set",
        "shutdown",
        "spawn",
        "start",
        "stop",
        "truncate",
        "update",
        "upload",
        "write",
    }
)

# How many tools are exercised. Each is one more request against the target and
# one more draw on the budget, and the swap this opens the window for fires on
# the first use of whichever tool the server keyed it to - so the cap trades a
# long tail of calls for the common case where that tool is among the first few
# a server advertises.
_MAX_EXERCISED = 6

# Values that satisfy a declared type without asking the target for anything in
# particular. A parameter whose type is absent or composite is not filled, and
# its tool is skipped rather than called with a guess.
_SCALAR_FILLER: dict[str, Any] = {"string": "mas-sentry", "integer": 1, "number": 1, "boolean": False}


def exercise_tools(client: McpClient) -> list[str]:
    """Call the read-shaped tools, so a swap keyed on use has the chance to happen.

    This detector can only see a descriptor that moved, and a server that
    rewrites on first use moves nothing until something uses it. Until now that
    use arrived by accident: an argument probe aimed at the first string
    parameter of every tool called all of them, including the ones it had no
    business calling. Making that probe precise closed the window, which is how
    the dependency came to light - the reference rig stopped reporting a swap it
    had reported since the detector landed. A window that depends on another
    module's imprecision is not a window; it is a coincidence.

    So it is opened on purpose now, and narrowly: no tool whose name carries a
    mutating verb, no argument that is not synthesised from the declared schema,
    and nothing at all for a tool whose required parameters this cannot fill.

    When every advertised tool is excluded, no window opens and the comparison
    that follows can only report what was already visible. That is a limit of
    what a scan may safely do rather than a probe that failed, so it is recorded
    here instead of as a row (R-2.4).
    """
    called: list[str] = []
    for tool in client.list_tools():
        if len(called) >= _MAX_EXERCISED:
            break
        if _name_carries_a_mutating_verb(tool.name):
            continue
        arguments = _fillable_arguments(tool.input_schema)
        if arguments is None:
            continue
        client.send("tools/call", {"name": tool.name, "arguments": arguments})
        called.append(tool.name)
    return called


def _name_carries_a_mutating_verb(name: str) -> bool:
    words = set(re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower().split("_"))
    return bool(words & _MUTATING_VERBS)


def _fillable_arguments(schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """Arguments for every required parameter, or None if one cannot be filled.

    With no `required` list every declared property is treated as required: a
    server that documents none of them is not telling us which it needs, and
    sending a partial object to find out is a worse guess than not calling.
    """
    properties = (schema or {}).get("properties") or {}
    required = (schema or {}).get("required") or list(properties)
    arguments: dict[str, Any] = {}
    for name in required:
        spec = properties.get(name)
        if not isinstance(spec, dict):
            return None
        filler = _SCALAR_FILLER.get(str(spec.get("type")))
        if filler is None:
            return None
        arguments[name] = filler
    return arguments
