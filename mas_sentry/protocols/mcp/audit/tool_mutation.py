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
`remove_tool`/`add_tool` emit nothing and the server advertises
`tools.listChanged: false`, so a server can rewrite its whole inventory in
silence. A detector waiting to be told would never fire, and an attacker has
every reason not to tell. Announcements are still read, because a server that
announces and a server that hides are not equally suspicious - but they are
read as evidence about the finding, never as the reason to look.

Comparison is between two enumerations MST performed itself, so there is no
heuristic to be wrong about: either the descriptor the server returned changed
or it did not.
"""

from __future__ import annotations

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
    """Digest every advertised tool descriptor as it stands right now."""
    return build_tool_baseline(client.list_tools())


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
