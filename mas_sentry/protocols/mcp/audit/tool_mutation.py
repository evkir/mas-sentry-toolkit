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
from dataclasses import dataclass, field
from typing import Any

from ..client import McpClient, ToolDef
from .descriptor import (
    BaselineEntry,
    arrival_evidence,
    build_tool_baseline,
    change_evidence,
    departure_evidence,
)

TOOLS_LIST_CHANGED = "notifications/tools/list_changed"


@dataclass(frozen=True, slots=True)
class MutationFinding:
    tool: str
    kind: str  # tool_mutation / tool_appeared / tool_withdrawn
    severity: str
    detail: str
    announced: bool
    # Both sides of whatever the row claims, in the same keys the between-runs
    # half of this class uses: a reviewer reads one shape whether the swap
    # crossed runs or happened under one scan (R-7.2). Empty for a row whose
    # entire content is its sentence, such as a listing that did not come back.
    evidence: dict[str, str] = field(default_factory=dict)


def snapshot_tools(client: McpClient) -> dict[str, BaselineEntry]:
    """Record every advertised tool descriptor as it stands right now.

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
    before: dict[str, BaselineEntry],
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

    for name, entry in sorted(after.items()):
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
                    evidence=arrival_evidence(entry),
                )
            )
        elif prior.digest != entry.digest:
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
                    evidence=change_evidence(prior, entry),
                )
            )

    for name, prior in sorted(before.items()):
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
                    evidence=departure_evidence(prior),
                )
            )
    return out


# A tool is called only if its name leads with one of these. The list admits
# rather than refuses, and that is the correction it makes: the selection used
# to be a list of verbs to refuse, which admits by default, so every
# destructive verb nobody had thought to enumerate was called. Measured on the
# reference rig before this changed, a default `mcp scan` called `wipe_disk`,
# `terminate_pod`, `revoke_token`, `overwrite_file` and `charge_card`, and the
# rig's `sweep_cluster` wrote its execution marker to disk.
#
# Being wrong now costs coverage: a swap keyed to a tool whose verb is absent
# here is never triggered and never seen. That is the direction this has to
# fail in, because the other one is paid by the target (R-7.6).
#
# Every verb here names retrieval of state the target already holds. `fetch`
# belongs with them - it returns a resource rather than changing one - and is
# the only entry whose call leaves the target at all, with an argument
# synthesised below that is not a URL.
_READ_VERBS = frozenset(
    {
        "count",
        "describe",
        "echo",
        "fetch",
        "find",
        "get",
        "head",
        "info",
        "inspect",
        "list",
        "ping",
        "query",
        "read",
        "search",
        "show",
        "stat",
        "status",
        "view",
    }
)

# Read as a veto on the rest of a name whose head already passed, which is the
# one shape the head test cannot judge: `get_and_delete_logs` leads with a
# retrieval verb and is not one. Kept from the previous selection, where it was
# the whole of it.
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

    So it is opened on purpose now, and narrowly: nothing but a name leading
    with a verb recognised as retrieval, nothing the target itself declares as
    writing, no argument that is not synthesised from the declared schema, and
    nothing at all for a tool whose required parameters this cannot fill.

    When every advertised tool is excluded, no window opens and the comparison
    that follows can only report what was already visible. That is a limit of
    what a scan may safely do rather than a probe that failed, so it is recorded
    here instead of as a row (R-2.4).
    """
    called: list[str] = []
    for tool in client.list_tools():
        if len(called) >= _MAX_EXERCISED:
            break
        if not _name_reads_as_retrieval(tool.name):
            continue
        if _target_declares_a_write(tool):
            continue
        arguments = _fillable_arguments(tool.input_schema)
        if arguments is None:
            continue
        client.send("tools/call", {"name": tool.name, "arguments": arguments})
        called.append(tool.name)
    return called


def _name_reads_as_retrieval(name: str) -> bool:
    """Whether the name leads with a retrieval verb and adds no mutating one."""
    words = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower().split("_")
    return words[0] in _READ_VERBS and not (set(words[1:]) & _MUTATING_VERBS)


def _target_declares_a_write(tool: ToolDef) -> bool:
    """Whether the target itself says this tool is not read-only.

    Read in one direction only. `readOnlyHint: false` narrows what MST will
    do; `readOnlyHint: true` widens nothing. A hint that could widen it would
    make the decision to call a tool the target's to make, and a server with a
    reason to be called has every reason to say so - which is the asymmetry
    R-2.4 asks for, applied to the target's own declarations.
    """
    annotations = tool.raw.get("annotations")
    if not isinstance(annotations, dict):
        return False
    return annotations.get("readOnlyHint") is False


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
