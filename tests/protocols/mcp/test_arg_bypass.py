# SPDX-License-Identifier: AGPL-3.0-or-later
"""Argument-bypass probing: three outcomes, and a verdict rebuilt from the wire.

Source: CVE-2026-85660 (`cli-mcp-server` <= 0.2.5, CVSS v4 9.2, CWE-78).
`_validate_command_with_operators` splits the command string on the shell
operators it knows, checks the head of each part against ALLOWED_COMMANDS, and
then hands the *original* string to `subprocess.run(..., shell=True)`. Command
substitution is in no operator list and is filtered nowhere, so an allowlisted
head carries an unlisted command past the check.

The cases below pin three properties the probe being replaced did not have.

- No file on the scanner host can produce a finding. The old probe confirmed a
  bypass by looking for a fixed canary path under /tmp, so any local user who
  created that path turned the next tool call into a CRITICAL finding, and the
  repository's own suite went red on a machine where the file already existed.
- An argument the server accepted without the marker appearing is a third
  outcome, not silence. The old probe dropped that case, which is the silent
  loss this project treats as its worst defect (R-2.1, R-7.5).
- The report row carries both sides, what was sent and what came back (R-7.2).
  A reviewer who cannot rebuild the verdict from evidence has no verdict.

The marker is arithmetic expansion, never a payload. `$((a*b))` is expanded by
the shell itself: no process is spawned and nothing is written anywhere.
Observing the product in place of the literal proves an unsanitised string
reached a shell, which is the path `$(...)` travels too - necessary and
sufficient, with no command of ours ever executed on the target.

Which command to put at the head is read off the wire, not guessed: the
vulnerable server publishes its own allowlist in the `run_command` descriptor
("Available commands: ..."), so the probe asks the target what it permits and
reports `allowlist-undisclosed` when the target says nothing (R-7.1).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.protocols.mcp.client import ToolDef

from .test_probe_results import _StubClient, _StubTransport, _text_result

runner = CliRunner()

# The historic canary path, hardcoded on purpose: this module stands guard so
# that a verdict keyed on the scanner's own filesystem cannot come back.
_HISTORIC_CANARY = Path("/tmp/mas-sentry-arginj")

# A descriptor shaped like the vulnerable server's: the allowlist is part of
# what the server advertises, which is where the probe is meant to read it.
_CMD_TOOL = [
    ToolDef(
        name="run_command",
        description="Allows command (CLI) execution in the directory: /srv\n\nAvailable commands: echo, pwd\n",
        input_schema={"type": "object", "properties": {"command": {"type": "string"}}},
    )
]

# A rig that reproduces the CVE rather than mocking it: every part of the
# command string is validated against the allowlist, and the whole original
# string is then handed to a shell. Comments only - no triple quotes - so the
# source survives being carried inside one.
_RIG = r"""
import json
import subprocess
import sys

ALLOWED = {"echo", "pwd"}
# Longest first, so '>>' is not split as two '>' parts.
OPERATORS = ("&&", "||", ">>", "<<", "|", ">", "<", ";")

TOOL = {
    "name": "run_command",
    "description": "Allows command (CLI) execution in the directory: /srv\n\nAvailable commands: echo, pwd\n",
    "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}}},
}


def parts_of(command_string):
    for op in OPERATORS:
        if op in command_string:
            return [p.strip() for p in command_string.split(op) if p.strip()]
    return [command_string]


def run_command(command_string):
    # The defect, verbatim in shape: each part's head is checked, then the
    # untouched string goes to a shell when an operator is present.
    for part in parts_of(command_string):
        head = part.split()[0] if part.split() else ""
        if head not in ALLOWED:
            return {"content": [{"type": "text", "text": "command not allowed: " + head}], "isError": True}
    if any(op in command_string for op in OPERATORS):
        done = subprocess.run(command_string, shell=True, capture_output=True, text=True, timeout=10)
    else:
        done = subprocess.run(command_string.split(), capture_output=True, text=True, timeout=10)
    return {"content": [{"type": "text", "text": done.stdout + done.stderr}]}


while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("id") is None:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "cli-mcp-rig", "version": "0.2.5"},
        }
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "tools/call":
        result = run_command(msg.get("params", {}).get("arguments", {}).get("command", ""))
    else:
        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "unknown"}}) + "\n"
        )
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


@pytest.fixture
def rig(tmp_path: Path) -> Path:
    path = tmp_path / "cli_rig.py"
    path.write_text(_RIG, encoding="utf-8")
    return path


@pytest.mark.xfail(strict=True, reason="O-4/c2: the probe still keys its verdict on a canary file")
def test_no_file_on_the_scanner_host_can_produce_a_finding() -> None:
    """A planted file is not evidence about the target.

    The guard is written so it only removes what it created: the path is a
    real artefact of older runs and deleting someone else's copy of it is not
    this test's business.
    """
    from mas_sentry.protocols.mcp.audit.arg_bypass import probe_argument_bypass

    planted = not _HISTORIC_CANARY.exists()
    if planted:
        _HISTORIC_CANARY.touch()
    try:
        client = _StubClient(_CMD_TOOL, _StubTransport(_text_result("command not allowed: echo", is_error=True)))
        out = probe_argument_bypass(client)  # type: ignore[arg-type]
        assert out, "a refusal is an observation and must be reported"
        assert [f.outcome for f in out if f.outcome != "blocked"] == []
    finally:
        if planted:
            _HISTORIC_CANARY.unlink(missing_ok=True)


@pytest.mark.xfail(strict=True, reason="O-4/c2: an accepted argument without the marker is dropped")
def test_an_accepted_argument_without_the_marker_is_inconclusive() -> None:
    """Accepted, but nothing proves the shell saw it - the third outcome.

    This is the false negative the canary produced: a server that let the
    argument through, yet whose payload did not land, was reported clean.
    """
    from mas_sentry.protocols.mcp.audit.arg_bypass import probe_argument_bypass

    client = _StubClient(_CMD_TOOL, _StubTransport(_text_result("done")))
    out = probe_argument_bypass(client)  # type: ignore[arg-type]
    assert out
    unresolved = [f for f in out if f.outcome == "inconclusive"]
    assert unresolved, "an accepted argument with no marker is neither a bypass nor a refusal"
    assert {f.reason for f in unresolved} == {"accepted-without-marker"}


@pytest.mark.xfail(strict=True, reason="O-4/c3: the row carries the payload only, not the observation")
@pytest.mark.skipif(sys.platform == "win32", reason="arithmetic expansion is POSIX shell syntax")
def test_the_report_row_carries_both_what_was_sent_and_what_came_back(rig: Path, tmp_path: Path) -> None:
    """Driven through `mcp scan` so the row is the one an operator reads (R-2.3)."""
    out = tmp_path / "scan.json"
    target = f"stdio://{sys.executable} {rig}"
    result = runner.invoke(app, ["mcp", "scan", "--target", target, "--checks", "traversal", "-o", str(out)])
    assert result.exit_code == 0, result.output
    rows = json.loads(out.read_text(encoding="utf-8"))

    hits = [r for r in rows if r["check"] == "shell_substitution"]
    assert hits, "the rig expands the marker, so the bypass must be reported"
    row = hits[0]
    assert row["sent_argument"], "what we sent"
    assert row["observed"], "what came back"
    assert row["expected_marker"] in row["observed"], "the verdict is rebuilt from the row alone"


def test_the_rig_reproduces_the_cve_it_stands_for(rig: Path) -> None:
    """The rig is the reality check: without the defect, nothing below is a test.

    Not xfailed - it pins the fixture, not the product, and must be green from
    the first commit. If the shell ever stops expanding the argument, every
    verdict in this module is measuring the rig instead of the probe.
    """
    if sys.platform == "win32":
        pytest.skip("arithmetic expansion is POSIX shell syntax")
    calls = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "run_command", "arguments": {"command": "echo MST=$((7*7)) ; echo tail"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "run_command", "arguments": {"command": "id"}},
        },
    ]
    stdin = "".join(json.dumps(c) + "\n" for c in calls)
    done = subprocess.run(
        [sys.executable, str(rig)], input=stdin, capture_output=True, text=True, timeout=60, check=False
    )
    replies = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    bypassed = json.dumps(replies[1])
    assert "MST=49" in bypassed, "the shell must expand the arithmetic the allowlist never saw"
    assert "7*7" not in bypassed, "the literal must not survive, or nothing was expanded"
    assert "command not allowed" in json.dumps(replies[2]), "an unlisted head must still be refused"
