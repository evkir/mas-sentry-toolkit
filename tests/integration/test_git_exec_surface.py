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


def _by_role(findings: list[dict], module: str, role: str) -> list[dict]:
    """Rows from one repository role.

    The rig carries two repositories on purpose, and both hold an executable
    key, so a case about one of them has to name which.
    """
    return [f for f in _rows(findings, module) if f["evidence"]["role"] == role]


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


def test_an_executable_key_in_a_delivered_git_config_is_reported(rig: dict[str, Path], tmp_path: Path) -> None:
    """A key that runs a program on `git status` leaves a row naming the key.

    HIGH because nothing stands between a checkout and the program: the
    operator opening the folder is the whole trigger, and `git status` is what
    an agent host runs first.
    """
    rows = _by_role(_audit(rig, tmp_path), "host.git_exec", "project")
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

    It turns red the moment a reader starts keeping the command instead of its
    shape, in the file an operator forwards with a ticket.
    """
    out = tmp_path / "reports" / "host.json"
    _audit(rig, tmp_path)
    assert str(rig["helper"]) not in out.read_text(encoding="utf-8")


def _plain(tmp_path: Path, config: str) -> dict[str, Path]:
    """A checkout with one config and nothing else to find, for the quiet cases."""
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir()
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo, home)
    (repo / ".git" / "config").write_text(config, encoding="utf-8")
    return {"home": home, "repo": repo}


def test_a_deliberate_command_is_medium_rather_than_high(rig: dict[str, Path], tmp_path: Path) -> None:
    """Severity follows the command measured to reach the key, not the key's name.

    `gpg.program` waits for `git commit -S`, so the operator has to mean it;
    `core.fsmonitor` fires on `git status`. Both rows exist and they are not
    worth the same.
    """
    (rig["repo"] / ".git" / "config").write_text(
        f"[core]\n\tfsmonitor = {rig['helper']}\n[gpg]\n\tprogram = {rig['helper']}\n",
        encoding="utf-8",
    )
    by_key = {r["evidence"]["key"]: r for r in _by_role(_audit(rig, tmp_path), "host.git_exec", "project")}
    assert by_key["core.fsmonitor"]["severity"] == "HIGH"
    assert by_key["gpg.program"]["severity"] == "MEDIUM"
    assert by_key["core.fsmonitor"]["evidence"]["passive"] is True
    assert by_key["gpg.program"]["evidence"]["passive"] is False


def test_hooks_path_is_high_because_git_status_reaches_it(rig: dict[str, Path], tmp_path: Path) -> None:
    """The one this would have got wrong by reasoning instead of measuring.

    `core.hooksPath` looks like it needs `git commit`. Driven against git
    2.43.0, `git status` reaches it through `post-index-change`, which puts it
    in the same class as `core.fsmonitor`.
    """
    (rig["repo"] / ".git" / "config").write_text(f"[core]\n\thooksPath = {rig['repo'].parent}\n", encoding="utf-8")
    (row,) = _by_role(_audit(rig, tmp_path), "host.git_exec", "project")
    assert row["evidence"]["key"] == "core.hookspath"
    assert row["severity"] == "HIGH"
    assert "post-index-change" in row["evidence"]["reached_by"]


def test_a_boolean_value_produces_no_row(tmp_path: Path) -> None:
    """The measured half of R-2.4: `fsmonitor = true` is git's own monitor.

    It runs no program, so a row here would fire on every repository that uses
    the built-in monitor - a check nobody can pass by doing it right.
    """
    rig = _plain(tmp_path, "[core]\n\tfsmonitor = true\n\thooksPath = false\n")
    assert _rows(_audit(rig, tmp_path), "host.git_exec") == []


def test_an_ordinary_repository_config_produces_no_row(tmp_path: Path) -> None:
    """The other half: what `git init` writes, plus a remote, must stay silent.

    This is the config on every checkout in existence. A row here would make
    the detector unusable on the first repository an operator pointed it at.
    """
    rig = _plain(
        tmp_path,
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
        '[remote "origin"]\n\turl = https://example.test/x.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
        '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n',
    )
    assert _rows(_audit(rig, tmp_path), "host.git_exec") == []


def test_a_protected_scope_only_key_produces_no_row(tmp_path: Path) -> None:
    """`uploadpack.packObjectsHook` executes nothing from a repository file.

    Git honours it only from protected configuration, measured rather than read
    off a page, so judging it would be the Scope-column false positive R-2.12
    exists to prevent.
    """
    rig = _plain(tmp_path, "[uploadpack]\n\tpackObjectsHook = /opt/evil/run.sh\n")
    assert _rows(_audit(rig, tmp_path), "host.git_exec") == []


def test_a_key_behind_an_include_is_reported_against_the_file_that_holds_it(tmp_path: Path) -> None:
    """A key the config only points at still reaches the report, named by origin.

    Measured: git honours `include.path` from a repository's own config. The
    row has to name the file the key actually sits in, or an operator opening
    `.git/config` would not find what the row is about.
    """
    side = tmp_path / "side.cfg"
    side.write_text("[core]\n\tfsmonitor = /opt/evil/run.sh\n", encoding="utf-8")
    rig = _plain(tmp_path, f"[include]\n\tpath = {side}\n")
    (row,) = _rows(_audit(rig, tmp_path), "host.git_exec")
    assert row["evidence"]["key"] == "core.fsmonitor"
    assert row["evidence"]["origin"] == str(side)
    assert row["evidence"]["scope"] == "included", "an included file is not local scope, and the row says so"


def test_the_row_carries_the_rule_it_is_judged_against(rig: dict[str, Path], tmp_path: Path) -> None:
    """R-7.2: the reviewer rebuilds the verdict from the row, not from its sentence.

    Both sides have to be there - what was observed, and the bound it is
    measured against - and the bound is quoted from git's own documentation
    rather than paraphrased by the scanner.
    """
    (row,) = _by_role(_audit(rig, tmp_path), "host.git_exec", "project")
    evidence = row["evidence"]
    assert evidence["role"] == "project"
    assert evidence["repository"] == ".git"
    assert evidence["value_form"] == "literal"
    assert "not protected" in evidence["scope_rule"]
    assert "cloned repository" in evidence["scope_rule"]


def test_a_git_config_row_carries_its_cwe_into_sarif(rig: dict[str, Path], tmp_path: Path) -> None:
    """The lens an operator filters by, in the file they open (R-2.1).

    CWE-15 is the CNA's attribution for CVE-2026-19592 and CVE-2026-19593. A
    row that reached SARIF without it would be invisible to the filter the
    triage runs on.
    """
    _audit(rig, tmp_path)
    out = tmp_path / "git.sarif.json"
    result = runner.invoke(
        app,
        [
            "report",
            "convert",
            str(tmp_path / "reports" / "host.json"),
            "-f",
            "sarif",
            "-o",
            str(out),
            "--target",
            "host",
        ],
    )
    assert result.exit_code == 0, result.stdout
    text = out.read_text(encoding="utf-8")
    assert "CWE-15" in text
    assert str(rig["helper"]) not in text
