# SPDX-License-Identifier: AGPL-3.0-or-later
"""The stdio launch the product actually performs, against the one it was told to."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.cli.mcp_cmd import _stdio_environment
from mas_sentry.protocols.mcp.runtime import run_mcp_scan

runner = CliRunner()

# Answers initialize and tools/list over newline-delimited JSON, naming itself
# after what it was launched with. A server that reports its own environment is
# the only way to prove the environment reached it.
SERVER = r"""
import json
import os
import sys

MARK = os.environ.get("MST_LAB_MARK", "unset")
HERE = os.path.basename(os.getcwd())
LEAK = "yes" if "MST_LAB_SECRET" in os.environ else "no"

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
    if msg.get("method") == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": f"mark={MARK} cwd={HERE} leak={LEAK}", "version": "0"},
        }
    elif msg.get("method") == "tools/list":
        result = {"tools": []}
    else:
        # Unknown methods have to be refused, or the stateless server/discover
        # route reads an empty success as a modern server describing itself.
        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "unknown"}}) + "\n"
        )
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


def _fingerprint(findings: list[dict[str, str]]) -> str:
    return next(f["detail"] for f in findings if f["check"] == "fingerprint")


@pytest.fixture
def server(tmp_path: Path) -> Path:
    path = tmp_path / "server.py"
    path.write_text(SERVER)
    return path


def test_the_environment_and_directory_reach_the_launched_target(server: Path, tmp_path: Path) -> None:
    """The point of the whole step: what the caller describes is what runs.

    StdioConfig has carried env and cwd since it was written; run_mcp_scan
    passed neither, so a unit test of the transport could pass while the
    product could not launch a target the way a client does.
    """
    workdir = tmp_path / "elsewhere"
    workdir.mkdir()
    findings = run_mcp_scan(
        scheme="stdio",
        command=[sys.executable, str(server)],
        target_label="stdio://server",
        checks="fingerprint",
        out=tmp_path / "out.json",
        scope_confirmed=False,
        budget_seconds=30.0,
        env={"MST_LAB_MARK": "delivered", "PATH": os.environ["PATH"]},
        cwd=str(workdir),
    )
    assert "mark=delivered" in _fingerprint(findings)
    assert "cwd=elsewhere" in _fingerprint(findings)


def test_a_named_environment_replaces_the_scanner_own(server: Path, tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A variable the operator did not name does not travel to the target."""
    monkeypatch.setenv("MST_LAB_SECRET", "operator-token")
    findings = run_mcp_scan(
        scheme="stdio",
        command=[sys.executable, str(server)],
        target_label="stdio://server",
        checks="fingerprint",
        out=tmp_path / "out.json",
        scope_confirmed=False,
        budget_seconds=30.0,
        env={"MST_LAB_MARK": "named", "PATH": os.environ["PATH"]},
    )
    assert "leak=no" in _fingerprint(findings)


def test_env_and_cwd_are_refused_for_a_target_that_is_not_launched(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="stdio targets only"):
        run_mcp_scan(
            scheme="https",
            command="https://mcp.example.com/mcp",
            target_label="https://mcp.example.com/mcp",
            checks="fingerprint",
            out=tmp_path / "out.json",
            scope_confirmed=True,
            env={"A": "b"},
        )


def test_assignments_split_on_the_first_equals_only() -> None:
    assert _stdio_environment(["DSN=postgres://u:p@h/db?x=1"], []) == {"DSN": "postgres://u:p@h/db?x=1"}


def test_an_assignment_without_a_value_is_refused() -> None:
    for bad in ("NOVALUE", "=orphan"):
        with pytest.raises(typer.BadParameter, match="KEY=VALUE"):
            _stdio_environment([bad], [])


def test_passthrough_copies_from_this_shell(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("MST_LAB_TOKEN", "from-shell")
    assert _stdio_environment([], ["MST_LAB_TOKEN"]) == {"MST_LAB_TOKEN": "from-shell"}


def test_passthrough_of_a_variable_that_is_not_set_is_an_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Launching without it would scan a target configured other than as described."""
    monkeypatch.delenv("MST_LAB_ABSENT", raising=False)
    with pytest.raises(typer.BadParameter, match="not set in this environment"):
        _stdio_environment([], ["MST_LAB_ABSENT"])


def test_nothing_named_leaves_the_launch_as_it_was() -> None:
    """None is inheritance, which is what every scan did before this step."""
    assert _stdio_environment([], []) is None


def test_the_cli_refuses_env_for_an_http_target(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["mcp", "scan", "-t", "http://127.0.0.1:1/mcp", "--env", "A=b", "-o", str(tmp_path / "o.json")],
    )
    assert result.exit_code != 0
    # Rich wraps the error into a panel, so a longer phrase would be split
    # across borders wherever the terminal width falls.
    assert "apply to stdio://" in " ".join(result.output.split())
    assert not (tmp_path / "o.json").exists(), "a report was written for a scan that never ran"


def test_the_cli_carries_the_environment_into_the_scan(server: Path, tmp_path: Path) -> None:
    """The path from the flag to the subprocess, exercised end to end.

    A parser tested on its own says the string was read, not that the launch
    used it.
    """
    out = tmp_path / "cli.json"
    result = runner.invoke(
        app,
        [
            "mcp",
            "scan",
            "-t",
            f"stdio://{sys.executable} {server}",
            "--checks",
            "fingerprint",
            "--env",
            "MST_LAB_MARK=via-cli",
            "-o",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    rows = json.loads(out.read_text())
    assert "mark=via-cli" in _fingerprint(rows)
