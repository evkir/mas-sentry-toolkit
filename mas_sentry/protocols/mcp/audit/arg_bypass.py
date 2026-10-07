# SPDX-License-Identifier: AGPL-3.0-or-later
"""Probe whether a tool argument reaches a shell from behind a command allowlist.

Source: CVE-2026-85660 (`cli-mcp-server` <= 0.2.5, CVSS v4 9.2, CWE-78).
`_validate_command_with_operators` splits the command string on the shell
operators it knows, checks the head of each part against ALLOWED_COMMANDS, and
then hands the *original* string to `subprocess.run(..., shell=True)`. Command
substitution appears in no operator list and is filtered nowhere, so an
allowlisted head carries an unlisted command past a check that passed.

What the probe observes, and what it refuses to do
--------------------------------------------------
The marker is arithmetic expansion, never a payload. `$((a*b))` is expanded by
the shell itself, before any command runs: no process is spawned, nothing is
written, nothing of ours executes on the target (R-7.6). Seeing the product
where the literal was sent proves an unsanitised string reached a shell, and
that is the same path `$(...)` and a backtick travel - necessary and sufficient
for the class, without standing up the class's consequence.

The factors are drawn per attempt rather than fixed. The probe this replaces
confirmed a bypass by looking for a fixed canary path under /tmp, which made
the verdict a statement about the scanner's own filesystem: any local user who
created that path turned the next tool call into a CRITICAL finding, and the
repository's own suite went red on a machine where the file happened to exist.
A product nobody can predict cannot be planted. The verdict stays reproducible
because both the expected product and the response travel in the finding, so a
reviewer rebuilds it from the row rather than from trust (R-7.2).

Three outcomes, because two of them are not enough
-------------------------------------------------
`bypassed` is the marker observed. `blocked` is a refusal, which is an
observation about the target and is reported rather than dropped. `inconclusive`
is the case the old probe lost in silence: the server accepted the argument and
answered, yet nothing came back to prove a shell ever saw it (R-2.1, R-7.5).

The marker outranks the error flag, and that ordering is the point. A command
that runs and then fails - `ls MST120000` cannot find that path - answers with
`isError` set and the expanded product inside its message. That is a confirmed
bypass. Reading the flag first, as the old probe did, filed it as a denial.

Where the allowlist comes from
------------------------------
Which command to put at the head is read off the wire: the vulnerable server
publishes its own allowlist in the `run_command` descriptor ("Available
commands: ls, cat"), so the probe asks the target what it permits instead of
guessing (R-7.1). Only that one shape is parsed, because it is the only one
with a source behind it; a target that discloses nothing is reported
`allowlist-undisclosed` rather than brute-forced.

Shapes deliberately left out
----------------------------
Two shapes ship, one per mechanism that can put a string in front of a shell:
bare, for an implementation that uses a shell unconditionally, and after an
operator, for one that reaches a shell only once an operator appears, which is
the mechanism the CVE describes. The `--config=/dev/stdin`, repeated-flag and
`-e`/`--eval` shapes are not here: no first-party advisory ties them to this
class, and a shape without a source is a guess (R-1.3, R-2.4). Flag injection
proper - `--upload-pack=`, `-oProxyCommand=` - is a different weakness with a
different fix (CWE-88, an allowlist of flags, against CWE-78, not reaching a
shell at all) and stays in its own probe.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass

from ..client import McpClient, ToolDef
from ..content import is_tool_error, tool_result_text

BYPASSED = "bypassed"
BLOCKED = "blocked"
INCONCLUSIVE = "inconclusive"

# The descriptor shape the vulnerable server publishes. Matched case-insensitively
# and stopped at the newline, because the descriptor continues with the flag list
# on the following line.
_ALLOWLIST_IN_DESCRIPTION = re.compile(r"(?:available|allowed)\s+commands?\s*:\s*([^\n]+)", re.IGNORECASE)

# The phrase the same descriptor uses when no allowlist is configured at all.
_OPEN_ALLOWLIST = "all commands"

# Parameters that carry a command line. A tool whose schema has none of them is
# left alone: sending a shell form to a parameter that was never a command
# produces noise rather than evidence, and the probe this replaces aimed at the
# first string parameter it found, whatever that parameter meant (R-2.4).
_COMMAND_PARAMS = frozenset({"command", "cmd", "commandline", "command_line", "shell", "script", "exec"})

# How many disclosed commands are tried. One call goes out per command per
# shape, so a server advertising thirty of them would turn one check into sixty
# tool calls. Four is enough to get past the common case where the first
# command listed ignores its arguments and so cannot echo a marker back, and
# the target's own ordering is kept rather than second-guessed.
_MAX_HEADS = 4

# How much of the response travels in the finding. Bounded because a command
# that succeeds can return a whole directory listing, and the row is evidence
# for a reviewer, not a transcript.
_MAX_OBSERVED = 240


@dataclass(frozen=True, slots=True)
class BypassFinding:
    """One attempt against one tool, with both sides of the comparison.

    `shape` and `expected_marker` are empty when no attempt was made, which
    happens only when the target disclosed no allowlist to clear.
    """

    tool: str
    shape: str
    outcome: str
    reason: str
    sent_argument: str
    observed: str
    expected_marker: str


def probe_argument_bypass(client: McpClient) -> list[BypassFinding]:
    out: list[BypassFinding] = []
    for tool in client.list_tools():
        param = _command_param(tool)
        if param is None:
            continue
        heads = _disclosed_heads(tool)
        if heads is None:
            out.append(
                BypassFinding(
                    tool=tool.name,
                    shape="",
                    outcome=INCONCLUSIVE,
                    reason="allowlist-undisclosed",
                    sent_argument="",
                    observed="the descriptor names no permitted commands",
                    expected_marker="",
                )
            )
            continue
        if not heads:
            # An open allowlist is not this weakness. There is no restriction to
            # clear, so a row here would report the operator's configuration as
            # a bypass of itself.
            continue
        for head in heads:
            for shape, argument, marker in _attempts_for(head):
                out.append(_attempt(client, tool.name, param, shape, argument, marker))
    return out


def _attempts_for(head: str) -> list[tuple[str, str, str]]:
    """The shapes to send for one allowlisted head, each with a fresh marker.

    A marker per attempt rather than per scan, so one expansion cannot be
    mistaken for another when several heads answer.
    """
    fragment, marker = _marker_pair()
    bare = (f"{head} {fragment}", marker)
    fragment, marker = _marker_pair()
    chained = (f"{head} {fragment} ; {head}", marker)
    return [
        ("arith_bare", *bare),
        ("arith_after_operator", *chained),
    ]


def _marker_pair() -> tuple[str, str]:
    """The fragment to send and the product to look for.

    The prefix keeps the match from being accidental: a bare five-digit product
    could occur in a directory listing, `MST120000` does not.
    """
    left = secrets.randbelow(400) + 300
    right = secrets.randbelow(400) + 300
    return f"MST$(({left}*{right}))", f"MST{left * right}"


def _attempt(client: McpClient, tool_name: str, param: str, shape: str, argument: str, marker: str) -> BypassFinding:
    resp = client.send("tools/call", {"name": tool_name, "arguments": {param: argument}})
    body = str(resp.error) if resp.is_error else tool_result_text(resp.result)
    observed = body[:_MAX_OBSERVED]
    if marker in body:
        return BypassFinding(
            tool=tool_name,
            shape=shape,
            outcome=BYPASSED,
            reason="marker-expanded",
            sent_argument=argument,
            observed=observed,
            expected_marker=marker,
        )
    if resp.is_error or is_tool_error(resp.result):
        return BypassFinding(
            tool=tool_name,
            shape=shape,
            outcome=BLOCKED,
            reason="refused",
            sent_argument=argument,
            observed=observed,
            expected_marker=marker,
        )
    return BypassFinding(
        tool=tool_name,
        shape=shape,
        outcome=INCONCLUSIVE,
        reason="accepted-without-marker",
        sent_argument=argument,
        observed=observed,
        expected_marker=marker,
    )


def _command_param(tool: ToolDef) -> str | None:
    for name, spec in ((tool.input_schema or {}).get("properties") or {}).items():
        if not isinstance(spec, dict) or spec.get("type") != "string":
            continue
        if name.lower().replace("-", "_") in _COMMAND_PARAMS:
            return name
    return None


def _disclosed_heads(tool: ToolDef) -> list[str] | None:
    """Commands the target says it permits, or None when it says nothing.

    An empty list is not the same answer as None: it means the descriptor did
    declare its allowlist and declared it open, where there is no restriction
    to clear. None means the target disclosed nothing, which the caller reports
    rather than working around.

    Heads that are not a bare word are dropped. Anything else would have to be
    quoted or escaped to survive the trip, and a probe that has to construct a
    shell word to ask its question is no longer asking a clean one.
    """
    found = _ALLOWLIST_IN_DESCRIPTION.search(tool.description or "")
    if not found:
        return None
    listed = found.group(1)
    if _OPEN_ALLOWLIST in listed.lower():
        return []
    heads = [part.strip() for part in listed.split(",")]
    return [head for head in heads if head.replace("-", "").replace("_", "").isalnum()][:_MAX_HEADS]
