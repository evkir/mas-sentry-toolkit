# SPDX-License-Identifier: AGPL-3.0-or-later
"""`--fail-on` across the CLI surface.

The exit codes are asserted through `host audit`, which is the one scan that
needs no broker, no SDK and no network to produce findings on demand. The
presence of the option is asserted across every command, because the claim being
made is that a scan can gate CI - not that one of them can.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import typer
import typer.main
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.cli.fail_on import enforce_fail_on
from mas_sentry.core.gating import FINDINGS_EXIT_CODE

runner = CliRunner()

# `report convert` renders findings somebody else produced and `doctor` inspects
# the environment. Neither assesses a target, so neither has anything to gate on.
_NOT_SCANS = {("report", "convert"), ("doctor",)}


def _every_command() -> list[tuple[str, ...]]:
    """Every invocable command path in the CLI, derived from the app itself.

    Derived rather than listed, so a scan command added without `--fail-on`
    fails this test instead of quietly joining an exemption list.
    """
    group = typer.main.get_command(app)
    out: list[tuple[str, ...]] = []
    for name, cmd in sorted(group.commands.items()):
        subs = sorted(getattr(cmd, "commands", {}) or {})
        out.extend((name, sub) for sub in subs) if subs else out.append((name,))
    return out


def _audit(tmp_path: Path, *extra: str) -> tuple[int, str]:
    result = runner.invoke(
        app,
        [
            "host",
            "audit",
            "--home",
            str(tmp_path / "home"),
            "--project-root",
            str(tmp_path / "repo"),
            "--out",
            str(tmp_path / "host.json"),
            *extra,
        ],
    )
    return result.exit_code, result.output


def _resolve(path: tuple[str, ...]) -> Any:
    """The command object one CLI path refers to.

    Typed as Any rather than click.Command: typer does not install click as a
    dependency of this project, so importing it for an annotation would make the
    suite fail to collect wherever only the declared dependencies are present -
    which is every clean install, including CI.
    """
    cmd: Any = typer.main.get_command(app)
    for part in path:
        cmd = cmd.commands[part]
    return cmd


@pytest.mark.parametrize("path", _every_command(), ids=lambda p: " ".join(p))
def test_every_scanning_command_offers_the_gate(path: tuple[str, ...]) -> None:
    """Asked of the command's parameters, not of its rendered help.

    `--help` output is not a stable string. Rich forces colour when it detects
    GitHub Actions, and it styles each segment of an option name separately, so
    `--fail-on` arrives as `-`, `-fail` and `-on` wrapped in escape sequences
    and no substring search finds it - which is how this test passed on two
    developer machines and failed on all four CI interpreters at once. The
    option either exists on the command or it does not, and that is the question
    worth asking.
    """
    options = {opt for param in _resolve(path).params for opt in param.opts}
    offered = "--fail-on" in options
    if path in _NOT_SCANS:
        assert not offered, f"{' '.join(path)} assesses no target and should not offer a gate"
    else:
        assert offered, f"{' '.join(path)} produces findings and must be able to gate CI"


def test_without_the_flag_the_exit_status_is_unchanged(tmp_path: Path) -> None:
    """Every release so far exited 0 whatever it found; the default must stay that way."""
    (tmp_path / "home").mkdir()
    (tmp_path / "repo").mkdir()
    code, _ = _audit(tmp_path)
    assert code == 0


def test_a_finding_below_the_threshold_does_not_fail(tmp_path: Path) -> None:
    """An empty machine reports one INFO row, which `--fail-on medium` must ignore."""
    (tmp_path / "home").mkdir()
    (tmp_path / "repo").mkdir()
    code, _ = _audit(tmp_path, "--fail-on", "medium")
    assert code == 0


def test_a_finding_at_the_threshold_fails_and_says_why(tmp_path: Path) -> None:
    (tmp_path / "home").mkdir()
    (tmp_path / "repo").mkdir()
    code, output = _audit(tmp_path, "--fail-on", "info")
    assert code == FINDINGS_EXIT_CODE
    assert "[fail-on info]" in output
    assert "INFO x1" in output


def test_a_gap_row_trips_a_medium_gate(tmp_path: Path) -> None:
    """The unreadable-config gap is MEDIUM, so a pipeline gating on medium catches it."""
    (tmp_path / "home" / ".cursor" / "mcp.json").mkdir(parents=True)
    (tmp_path / "repo").mkdir()
    code, output = _audit(tmp_path, "--fail-on", "medium")
    assert code == FINDINGS_EXIT_CODE
    assert "MEDIUM x1" in output


def test_an_unknown_threshold_is_a_usage_error_not_a_gate_failure(tmp_path: Path) -> None:
    """And it is raised before the scan: a typo found at the end wastes the run."""
    (tmp_path / "home").mkdir()
    (tmp_path / "repo").mkdir()
    code, output = _audit(tmp_path, "--fail-on", "warn")
    assert code == 2, "a bad threshold is a broken invocation, not a scan result"
    assert "unknown severity" in output
    assert not (tmp_path / "host.json").exists(), "the scan must not have run"


def test_an_unreadable_severity_fails_the_gate_and_names_the_value() -> None:
    """Driven directly: the CLI reaches this branch only through a module bug.

    No command emits a non-severity today, so there is no invocation that would
    exercise it - and the branch has to work, because the alternative design was
    a gate that silently passed the row.
    """
    with pytest.raises(typer.Exit) as raised:
        enforce_fail_on(["CRITICAL", "nonsense"], "high")
    assert raised.value.exit_code == FINDINGS_EXIT_CODE


def test_no_threshold_means_the_gate_is_never_consulted() -> None:
    """The default path, asserted on the helper as well as through the command."""
    enforce_fail_on(["CRITICAL"], None)


def test_the_report_is_still_written_when_the_gate_fails(tmp_path: Path) -> None:
    """Gating must not cost the artefact: CI needs the report precisely when it fails."""
    (tmp_path / "home").mkdir()
    (tmp_path / "repo").mkdir()
    code, _ = _audit(tmp_path, "--fail-on", "info")
    assert code == FINDINGS_EXIT_CODE
    payload = json.loads((tmp_path / "host.json").read_text())
    assert payload["findings"]
