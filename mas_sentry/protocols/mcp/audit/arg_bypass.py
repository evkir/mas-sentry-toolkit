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
Two substitution shapes ship, one per mechanism that can put a string in front
of a shell: bare, for an implementation that uses a shell unconditionally, and
after an operator, for one that reaches a shell only once an operator appears,
which is the mechanism the CVE describes. The `--config=/dev/stdin`,
repeated-flag and `-e`/`--eval` shapes are not here: no first-party advisory
ties them to this class, and a shape without a source is a guess (R-1.3, R-2.4).

The second weakness in this module
----------------------------------
Flag injection is the other way an argument goes where it should not, and it is
a different weakness with a different fix: an allowlist of flags, against not
reaching a shell at all. So it carries CWE-88 while substitution carries CWE-78,
and it gets its own probe - but the same three outcomes and the same finding
type, because the question it asks is identical. Source: CVE-2025-68144
(`mcp-server-git` < 2025.12.17, GHSA-9xwc-hfwc-8w59), where a caller's value is
split into argv with no `--` separator and a leading dash is read as an option.

`-oProxyCommand=` is not among its shapes. The principle fits, but no ssh client
was available to observe it with, and a shape nobody watched work is the same
guess as a shape nobody sourced (R-2.4).
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


def _attempt(
    client: McpClient,
    tool_name: str,
    param: str,
    shape: str,
    argument: str,
    marker: str,
    confirmed_reason: str = "marker-expanded",
) -> BypassFinding:
    resp = client.send("tools/call", {"name": tool_name, "arguments": {param: argument}})
    body = str(resp.error) if resp.is_error else tool_result_text(resp.result)
    observed = body[:_MAX_OBSERVED]
    if _marker_stands_alone(marker, body):
        return BypassFinding(
            tool=tool_name,
            shape=shape,
            outcome=BYPASSED,
            reason=confirmed_reason,
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


def _marker_stands_alone(marker: str, body: str) -> bool:
    """True when the marker arrives as a word of its own, not inside an echo.

    A target that refuses an option quotes the option back whole. git answers
    ``error: unknown option `exec=MST782577'`` to a `--exec=` it does not
    accept, and a plain substring test reads that refusal as a confirmation -
    a false positive on a target that did the right thing, which is the half of
    R-2.4 that is easy to miss.

    The difference is positional and holds for both weaknesses here. A value
    that was *used* - as a program name, or as the product of an expansion -
    arrives as its own word. A value that was merely quoted arrives still
    attached to the `=` of the option that carried it. Caught live against git
    2.43.0, where the confirmed case read `MST592491 '/repo/.git': 1:
    MST592491: not found` and the refused one read as above.
    """
    return re.search(rf"(?<![=\w-]){re.escape(marker)}", body) is not None


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


# Options that name a program for the binary to run. Both verified against git
# 2.43.0: the binary quotes the name back when it cannot run it, which is the
# whole observation - `--upload-pack=` on a local clone and `--exec=` on
# `git archive --remote` both answered `MST9182736 '<repo>': 1: MST9182736: not
# found`, while a clean value cloned with no marker anywhere (R-2.2, R-2.4).
_FLAG_SHAPES = (
    ("upload_pack", "--upload-pack={marker}"),
    ("exec", "--exec={marker}"),
)

# Parameter words that carry a value a git-like tool passes into argv. Read off
# the installed `mcp-server-git` 2026.8.18 schema rather than guessed: its
# fields are repo_path, target, revision, branch_name, base_branch, contains and
# not_contains. `message` is deliberately absent - it travels as the value of
# `-m`, where a leading dash is not read as an option.
_ARGUMENT_WORDS = frozenset(
    {"path", "repo", "repository", "target", "revision", "ref", "branch", "remote", "source", "upstream", "contains"}
)

# How many matching parameters are tried per tool. Each gets both shapes, and a
# tool can declare several argv-bearing parameters, so the cap keeps one tool
# from issuing a handful of calls on its own. The schema's own order is kept.
_MAX_PARAMS = 2


def probe_flag_injection(client: McpClient) -> list[BypassFinding]:
    """Send an option naming a program that does not exist, and read the echo.

    Confirmation is the name coming back, which proves the option reached the
    binary and was used as a program. Nothing of ours runs, because there is
    nothing by that name to run - the opposite of the canary this replaces,
    which executed `touch` and then asked the scanner's own filesystem whether
    the target had misbehaved.

    Not observable this way: `--upload-pack` over https, which git ignores with
    "setting remote service path not supported by protocol". Such a target ends
    up `inconclusive`, which is a report, not a silence (R-7.5).
    """
    out: list[BypassFinding] = []
    for tool in client.list_tools():
        for param in _argument_params(tool):
            for shape, template in _FLAG_SHAPES:
                marker = _program_marker()
                out.append(
                    _attempt(
                        client,
                        tool.name,
                        param,
                        shape,
                        template.format(marker=marker),
                        marker,
                        confirmed_reason="marker-echoed",
                    )
                )
    return out


def _program_marker() -> str:
    """A program name nothing will resolve, fresh per attempt.

    Fresh for the same reason the arithmetic factors are: a fixed name is a name
    an attacker - or a stale run - can arrange to exist, and the verdict would
    then describe the environment instead of the target.
    """
    return f"MST{secrets.randbelow(900000) + 100000}"


def _argument_params(tool: ToolDef) -> list[str]:
    params = [
        name
        for name, spec in ((tool.input_schema or {}).get("properties") or {}).items()
        if isinstance(spec, dict) and spec.get("type") == "string" and _name_words(name) & _ARGUMENT_WORDS
    ]
    return params[:_MAX_PARAMS]


def _name_words(name: str) -> set[str]:
    """A parameter name split into words, so a word matches a word.

    Substring matching would make `resource_uri` look like a `source`
    parameter and send git options at a resource reader, which is the noise
    R-2.4 is about. camelCase is split too, because a schema may use either.
    """
    return set(re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower().split("_"))
