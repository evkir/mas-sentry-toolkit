# SPDX-License-Identifier: AGPL-3.0-or-later
"""Flag injection, confirmed by what the binary echoed rather than by a canary.

Source: CVE-2025-68144 (`mcp-server-git` < 2025.12.17, GHSA-9xwc-hfwc-8w59).
A caller-supplied value is split into argv without a `--` separator, so a value
that begins with a dash is read as an option. `--upload-pack=` and `--exec=`
both name a program for git to run, which is what turns an injected option into
execution.

Why this module exists even though a probe already covered the class
-------------------------------------------------------------------
The probe being replaced confirmed a hit by looking for `/tmp/mas-sentry-arginj`
after sending `--upload-pack=touch /tmp/mas-sentry-arginj`. Three consequences,
all of them defects:

- the verdict described the scanner's filesystem, not the target. A local user
  who created that path turned the next tool call into a CRITICAL finding, and
  the repository's own suite went red on a machine where the file existed.
- against an HTTP target the payload ran on the far side while `Path.exists()`
  looked on this side, so the probe could only ever confirm over stdio - and
  said so nowhere.
- it executed a payload to learn something, which is the one thing a scanner
  here does not do (R-7.6).

The replacement sends a program name that does not exist. git tries to run it
and quotes it back - `MST9182736 '/repo/.git': 1: MST9182736: not found` -
which proves the option reached the binary and was used as a program, while
nothing of ours ran. Verified against git 2.43.0 for `--upload-pack=` on a
local clone and `--exec=` on `git archive --remote`; a clean source answers
`done.` with no marker anywhere, which is the other half of R-2.4.

What it cannot see: `--upload-pack` is ignored over https, where git answers
"setting remote service path not supported by protocol". A target reached that
way returns `inconclusive`, not silence.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.protocols.mcp.client import ToolDef

from .test_probe_results import _StubClient, _StubTransport, _text_result

runner = CliRunner()

# The same historic canary path the bypass module guards, pinned here too: this
# is the probe it actually belonged to.
_HISTORIC_CANARY = Path("/tmp/mas-sentry-arginj")

_CLONE_TOOL = [
    ToolDef(
        name="clone_repo",
        description="Clone a repository",
        input_schema={"type": "object", "properties": {"source": {"type": "string"}}},
    )
]

# A rig in the vulnerable shape: the caller's value is split into argv and
# placed before the positional arguments, with no `--` to stop it being read as
# an option. That missing separator is the whole of CVE-2025-68144.
_RIG = r"""
import json
import shlex
import subprocess
import sys

REPO = sys.argv[1]
DEST = sys.argv[2]

TOOL = {
    "name": "clone_repo",
    "description": "Clone a repository",
    "inputSchema": {"type": "object", "properties": {"source": {"type": "string"}}},
}

counter = [0]


def clone_repo(source):
    counter[0] += 1
    dest = DEST + "/c" + str(counter[0])
    argv = ["git", "clone", *shlex.split(source), REPO, dest]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    except OSError as exc:
        return {"content": [{"type": "text", "text": "could not run git: " + str(exc)}], "isError": True}
    text = done.stdout + done.stderr
    return {"content": [{"type": "text", "text": text}], "isError": done.returncode != 0}


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
            "serverInfo": {"name": "git-rig", "version": "0.1.0"},
        }
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "tools/call":
        result = clone_repo(msg.get("params", {}).get("arguments", {}).get("source", ""))
    else:
        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "unknown"}}) + "\n"
        )
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="the rig drives a real git binary")


@pytest.fixture
def rig(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A rig script, an empty source repository for it, and a clone directory."""
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, timeout=60)
    identity = ["-c", "user.email=a@b", "-c", "user.name=a"]
    subprocess.run(
        ["git", "-C", str(repo), *identity, "commit", "-q", "--allow-empty", "-m", "i"],
        check=True,
        timeout=60,
    )
    dest = tmp_path / "clones"
    dest.mkdir()
    script = tmp_path / "git_rig.py"
    script.write_text(_RIG, encoding="utf-8")
    return script, repo, dest


def test_no_file_on_the_scanner_host_can_confirm_a_flag_injection() -> None:
    """A planted file is not evidence about the target.

    Only what this test created is removed: the path is a real artefact of older
    runs and deleting someone else's copy is not this test's business.
    """
    from mas_sentry.protocols.mcp.audit.arg_bypass import probe_flag_injection

    planted = not _HISTORIC_CANARY.exists()
    if planted:
        _HISTORIC_CANARY.touch()
    try:
        client = _StubClient(_CLONE_TOOL, _StubTransport(_text_result("option not allowed", is_error=True)))
        out = probe_flag_injection(client)  # type: ignore[arg-type]
        assert out, "a refusal is an observation and must be reported"
        assert [f for f in out if f.outcome == "bypassed"] == []
    finally:
        if planted:
            _HISTORIC_CANARY.unlink(missing_ok=True)


@needs_git
def test_a_flag_that_reached_the_binary_is_confirmed_by_the_echoed_name(rig: tuple[Path, Path, Path]) -> None:
    """git quotes the program it failed to run, and that name is the evidence."""
    from mas_sentry.protocols.mcp.audit.arg_bypass import probe_flag_injection
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    script, repo, dest = rig
    command = [sys.executable, str(script), str(repo), str(dest)]
    with open_stdio(StdioConfig(command=command, timeout=90.0)) as transport:
        client = McpClient(transport)
        client.connect()
        out = probe_flag_injection(client)

    hits = [f for f in out if f.outcome == "bypassed"]
    assert hits, "an injected option that reached git must be confirmed"
    hit = hits[0]
    assert hit.expected_marker in hit.observed, "the verdict is the echoed name, not a side effect"
    assert "touch" not in hit.sent_argument, "the probe must not send a payload that does anything"


@needs_git
def test_the_report_row_names_the_flag_and_what_came_back(rig: tuple[Path, Path, Path], tmp_path: Path) -> None:
    """Driven through `mcp scan` so the row is the one an operator reads (R-2.3)."""
    script, repo, dest = rig
    out = tmp_path / "scan.json"
    target = f"stdio://{sys.executable} {script} {repo} {dest}"
    result = runner.invoke(app, ["mcp", "scan", "--target", target, "--checks", "traversal", "-o", str(out)])
    assert result.exit_code == 0, result.output
    rows = json.loads(out.read_text(encoding="utf-8"))

    hits = [r for r in rows if r["check"] == "arg_injection"]
    assert hits, "the rig lets the option through, so the injection must be reported"
    row = hits[0]
    assert row["sent_argument"].startswith("-"), "the row names the flag that was sent"
    assert row["expected_marker"] in row["observed"], "the verdict is rebuilt from the row alone"


@needs_git
def test_the_rig_reproduces_the_cve_it_stands_for(rig: tuple[Path, Path, Path]) -> None:
    """The reality check: without the defect, nothing above is a test.

    Not xfailed - it pins the fixture, not the product, and must be green from
    this commit on. Both halves are asserted: an injected option is echoed back,
    and a clean source clones without any marker in sight, which is what keeps
    the confirmed case from being an artefact of the rig.
    """
    script, repo, dest = rig
    calls = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "clone_repo", "arguments": {"source": "--upload-pack=MST9182736"}},
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "clone_repo", "arguments": {"source": ""}},
        },
    ]
    stdin = "".join(json.dumps(c) + "\n" for c in calls)
    done = subprocess.run(
        [sys.executable, str(script), str(repo), str(dest)],
        input=stdin,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    replies = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
    injected = json.dumps(replies[1])
    assert "MST9182736" in injected, "git must quote back the program it could not run"
    assert "not found" in injected, "the name must have been used as a program, not as a path"
    assert "MST9182736" not in json.dumps(replies[2]), "a clean source must leave no marker behind"


def test_an_option_quoted_back_in_a_refusal_is_not_a_confirmation() -> None:
    """The false positive a substring test produces, with both live texts.

    Negative by construction, so it is green from the commit that introduces it
    (the R-2.6 exception). Both strings came off git 2.43.0: the first is how it
    refuses an option it does not know, the second is how it reports a program
    it could not run.
    """
    from mas_sentry.protocols.mcp.audit.arg_bypass import _marker_stands_alone

    refused = "error: unknown option `exec=MST782577'\nusage: git clone [<options>] [--] <repo>"
    executed = "MST592491 '/repo/.git': 1: MST592491: not found"
    assert not _marker_stands_alone("MST782577", refused), "a quoted option is not an execution"
    assert _marker_stands_alone("MST592491", executed), "a program name used as one must still confirm"
