# SPDX-License-Identifier: AGPL-3.0-or-later
"""The executable surface of a repository's own git configuration.

Source: GHSA-9ccr-r5hg-74gf (CVE-2026-45033, GitHub Copilot CLI), the Codex
cluster CVE-2026-19590 / -19592 / -19593, and git's own "Protected
configuration" section, which places `local` and `worktree` outside the trusted
scopes for the stated reason that those files may arrive with a clone.

Two deliveries, both measured against git 2.43.0 rather than taken from the
advisories.

The first is a checkout that arrives with its `.git` intact - an archive, a
copied folder, a shared drive. Thirteen keys then run a program the config
names, and two of them, `core.fsmonitor` and `diff.external`, are reached by
`git status` and `git diff`: the commands an agent host runs to show an
operator where they are. No trust prompt stands in front of either.

The second survives an ordinary clone, which the first does not. A directory
carrying `HEAD`, `config`, a file beneath `objects/` and a loose ref beneath
`refs/` is a repository as far as git is concerned, whatever it is named, and
git adopts it while walking up from a command run inside it or below it. Empty
directories are not carried by a commit, which is why a bare clone does not
work as the plant - its refs are packed and `refs/` is left empty - and a
hand-built tree does.

MST already names this class as the reason it will not run git inside a foreign
checkout (`host/executable.py`, R-7.6). The files that do it sit on disk and
parse without running anything, and the audit does not read them.

The rig runs git itself, and that is the reality check rather than a breach of
R-7.6: nothing in the product executes anything here, and an assertion that the
audit reports a plant would otherwise pass against a directory git ignores.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app

runner = CliRunner()

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="the rig needs git to prove it is a rig")


def _env(home: Path) -> dict[str, str]:
    """A git that reads no configuration but the one the case wrote.

    `GIT_CONFIG_NOSYSTEM` and a private HOME keep the operator's own global
    config out of the measurement: a developer with `core.fsmonitor` already
    set would otherwise see the marker appear for the wrong reason.
    """
    return {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "rig",
        "GIT_AUTHOR_EMAIL": "rig@example.invalid",
        "GIT_COMMITTER_NAME": "rig",
        "GIT_COMMITTER_EMAIL": "rig@example.invalid",
    }


def _git(args: list[str], cwd: Path, home: Path) -> str:
    out = subprocess.run(["git", *args], cwd=cwd, env=_env(home), capture_output=True, timeout=60, check=False)
    return (out.stdout + out.stderr).decode("utf-8", "replace")


def _marker_script(path: Path, marker: Path) -> Path:
    """A program that records having run, and does nothing else."""
    path.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 0\n', encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def rig(tmp_path: Path) -> dict[str, Path]:
    """A checkout delivered with its own `.git`, plus a planted repository inside it.

    One tree carries both deliveries, so a single `host audit` sees each of
    them and neither assertion depends on the other's fixture.
    """
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    marker = tmp_path / "MARKER"
    helper = _marker_script(tmp_path / "helper.sh", marker)

    _git(["init", "-q", "-b", "main"], repo, home)
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    _git(["add", "a.txt"], repo, home)
    _git(["commit", "-qm", "init"], repo, home)
    # The delivered config. `--local` writes .git/config, which is the file an
    # archive or a copied folder brings with it.
    _git(["config", "--local", "core.fsmonitor", str(helper)], repo, home)

    # The plant: the four files git needs, written by hand so each one is a
    # file and survives a commit. A loose ref rather than a packed one for the
    # same reason - `refs/` has to be non-empty.
    plant = repo / "vendor" / "thing"
    (plant / "refs" / "heads").mkdir(parents=True)
    (plant / "objects" / "info").mkdir(parents=True)
    (plant / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (plant / "refs" / "heads" / "main").write_text(f"{'0' * 40}\n", encoding="utf-8")
    (plant / "objects" / "info" / "packs").write_text("\n", encoding="utf-8")
    (plant / "config").write_text(
        f"[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tfsmonitor = {helper}\n[alias]\n\tll = !{helper}\n",
        encoding="utf-8",
    )
    return {"home": home, "repo": repo, "plant": plant, "marker": marker, "helper": helper}


def _audit(rig: dict[str, Path], tmp_path: Path) -> list[dict]:
    """One `host audit` over the rig, rows as the operator reads them."""
    out = tmp_path / "reports" / "host.json"
    result = runner.invoke(
        app,
        [
            "host",
            "audit",
            "--home",
            str(rig["home"]),
            "--project-root",
            str(rig["repo"]),
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.stdout
    findings: list[dict] = json.loads(out.read_text(encoding="utf-8"))["findings"]
    return findings


def _rows(findings: list[dict], module: str) -> list[dict]:
    return [f for f in findings if f["module"] == module]


def test_the_delivered_config_makes_an_ordinary_command_run_a_program(rig: dict[str, Path]) -> None:
    """The reality check for the first delivery, and the claim the audit rests on.

    Not xfailed: it pins the rig, not the product, and must be green from this
    commit on. Without it, a row the audit later produces would be asserted
    against a key that might do nothing on this git.
    """
    assert not rig["marker"].exists(), "the marker must not predate the command"
    _git(["status"], rig["repo"], rig["home"])
    assert rig["marker"].exists(), "git status has to run what .git/config names in core.fsmonitor"


def test_git_adopts_the_planted_directory_as_a_repository(rig: dict[str, Path]) -> None:
    """The reality check for the second delivery.

    Also not xfailed. A plant git declines is an ordinary directory, and an
    assertion that the audit reports one would pass for the wrong reason
    against a tree nothing would ever execute from.
    """
    assert _git(["rev-parse", "--git-dir"], rig["plant"], rig["home"]).strip() == "."
    assert _git(["rev-parse", "--is-bare-repository"], rig["plant"], rig["home"]).strip() == "true"
    below = rig["plant"] / "objects" / "info"
    assert _git(["rev-parse", "--git-dir"], below, rig["home"]).strip() == str(rig["plant"]), (
        "a command run below the plant has to resolve to it, which is how a tree walk arrives"
    )


@pytest.mark.xfail(strict=True, reason="the audit does not read the repository's own git config")
def test_an_executable_key_in_a_delivered_git_config_is_reported(rig: dict[str, Path], tmp_path: Path) -> None:
    """A key that runs a program on `git status` leaves a row naming the key.

    HIGH because nothing stands between a checkout and the program: the
    operator opening the folder is the whole trigger, and `git status` is what
    an agent host runs first.
    """
    rows = _rows(_audit(rig, tmp_path), "host.git_exec")
    assert rows, "a repository config that executes on git status must produce a row"
    row = rows[0]
    assert row["severity"] == "HIGH"
    assert row["evidence"]["key"] == "core.fsmonitor"
    assert row["evidence"]["scope"] == "local"


@pytest.mark.xfail(strict=True, reason="the audit does not look for directories git would adopt")
def test_a_planted_repository_directory_is_reported(rig: dict[str, Path], tmp_path: Path) -> None:
    """A directory git adopts, carried by the tree itself, leaves a row naming it.

    The path is relative to the project root: it is what the operator greps for
    in their own checkout, and an absolute one would differ on every machine.
    """
    rows = _rows(_audit(rig, tmp_path), "host.git_plant")
    assert rows, "a directory git adopts as a repository must produce a row"
    assert rows[0]["evidence"]["path"] == "vendor/thing"


def test_no_executable_payload_from_a_git_config_reaches_the_report(rig: dict[str, Path], tmp_path: Path) -> None:
    """R-7.3 for this surface, asserted now so no later step can quietly break it.

    Green from this commit: the audit reads none of these files yet, so nothing
    can leak. It turns red the moment a reader starts keeping the command
    instead of its shape.
    """
    out = tmp_path / "reports" / "host.json"
    _audit(rig, tmp_path)
    assert str(rig["helper"]) not in out.read_text(encoding="utf-8")
