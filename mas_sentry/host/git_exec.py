# SPDX-License-Identifier: AGPL-3.0-or-later
"""Judge the keys a repository's git configuration uses to run a program.

The reader (`git_surface.py`) says what the files declare. This says which of
those declarations is an execution path, how much it is worth, and why - and
nothing about the directories themselves, which is the next detector's.

Source: CVE-2026-19592 (Codex CLI) and CVE-2026-19593 (Codex Desktop), both
attributed by the CNA to **CWE-15, External Control of System or Configuration
Setting**, which is the lens below. CWE-829 is the one this package already
uses for a repository settings file that runs a command (`host.exec_hook`), and
it reads on the same class - but the first-party attribution for this class
names CWE-15, and an attribution beats a resemblance (R-2.13). CWE-696, which
GitHub assigned to GHSA-9ccr-r5hg-74gf, describes a host running git before its
own guard rather than anything about the configuration, so it is not used here.

The class was surveyed by Manifold Security as "GitSpawn" and published by the
Cloud Security Alliance on 2026-09-02: eight findings across seven coding
agents - Claude Code, Codex, Cursor, Goose, Qwen Code, Grok Build, Hermes Agent
- with four variants still exploitable at the time of writing. That note names
`core.fsmonitor` as the exploited key and says `core.hooksPath`,
`credential.helper` and the external diff and merge tools are "structurally
similar", without testing them. Its advice to operators is to run
`git config --get core.fsmonitor` by hand before letting an agent open a
repository. The table below is that advice, over every key measured to execute,
with no git command run at all (R-7.6).

Severity is one question, and it was measured rather than reasoned: does a
command the host runs on its own reach the key? The CSA note calls those
"background commands like `git status` or `git diff`", and each row below was
driven against git 2.43.0 with a marker script.

| key | measured | severity |
|---|---|---|
| `core.fsmonitor` | fires on `status`, `diff`, `add` | HIGH |
| `core.hooksPath` | fires on `status` via `post-index-change` | HIGH |
| `diff.external` | fires on `diff` | HIGH |
| everything else | needs commit, fetch, or a terminal | MEDIUM |

`core.hooksPath` was the one this would have got wrong by reasoning: the key
looks like it needs `git commit`, and the measurement showed `git status`
reaching it through `post-index-change`.

Two keys that execute are deliberately absent, each for a reason that would
otherwise make a false positive (R-2.4):

- `uploadpack.packObjectsHook` is honoured only from protected configuration,
  so a repository file setting it runs nothing. Measured, not assumed.
- `alias.<name>` executes a shell command when its value starts with `!`, and
  is an ordinary git subcommand otherwise. `alias.lg = log --oneline` is on a
  large share of real repositories, so a row for every alias would be noise -
  and the reader does not record whether a value starts with `!`, because no
  judge needed it until now. Judging aliases needs that distinction first.

A boolean value is not a program. `core.fsmonitor = true` selects git's own
built-in monitor, measured to run nothing, so the reader records booleans as
booleans and this judge skips them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from mas_sentry.core.finding import Finding, Severity

from .git_surface import GitConfigKey, GitRepoDir, GitSurface

# Every key measured to hand its value to a program, with the command that
# reaches it and whether that command is one a host runs without being asked.
# The command text is what an operator re-derives the verdict from, so it names
# what was actually driven rather than paraphrasing the key.
_EXECUTABLE_KEYS: Final[dict[str, tuple[str, bool]]] = {
    "core.fsmonitor": ("git status, git diff and git add", True),
    "core.hookspath": ("git status, through the post-index-change hook", True),
    "diff.external": ("git diff over a modified file", True),
    "core.editor": ("git commit with no -m", False),
    "core.pager": ("git log with output on a terminal", False),
    "core.sshcommand": ("git fetch over ssh", False),
    "core.gitproxy": ("git fetch over git://", False),
    "credential.helper": ("git credential fill, and any authenticated fetch", False),
    "gpg.program": ("git commit -S", False),
}

# Quoted rather than paraphrased, because a verdict a reviewer cannot rebuild
# from the row is not deterministic (R-7.2). From git-config, "Protected
# configuration".
_GIT_SCOPE_RULE: Final = (
    "git documents system, global and command scope as protected configuration and local and "
    "worktree scope as not protected, on the stated grounds that those files may come from a "
    "cloned repository"
)

# How the file a key came from maps onto git's scope names. Anything else is a
# file an include pointed at, which git applies at the scope of the file that
# named it; the row carries the path instead of guessing a scope for it.
_SCOPE_OF_FILE: Final = {"config": "local", "config.worktree": "worktree"}


def _scope(key: GitConfigKey) -> str:
    return _SCOPE_OF_FILE.get(key.origin, "included")


def _row(root: Path, repo: GitRepoDir, key: GitConfigKey, reached_by: str, passive: bool) -> Finding:
    """One key that runs a program, with both sides of the claim in the row.

    What was observed is the key, the file it sits in and the shape of its
    value; what it is compared against is git's own scope rule and the command
    measured to reach it. An operator rebuilds the verdict from those without
    the row carrying the command line itself (R-7.2, R-7.3).
    """
    where = "a repository directory the tree carries" if repo.role == "plant" else "this checkout's git directory"
    return Finding(
        module="host.git_exec",
        title=f"{repo.path}: {key.key} names a program git runs",
        detail=(
            f"{key.key} is set in {repo.path}/{key.origin} and git hands its value to a program on "
            f"{reached_by}. The file sits in {where}, and {_GIT_SCOPE_RULE}. "
            + (
                "That command is one a host runs to orient itself, so opening the folder is the whole "
                "trigger - no prompt stands in front of it. "
                if passive
                else "That command is a deliberate one, so the key waits for it rather than firing on arrival. "
            )
            + "Confirm you set this key yourself: this audit reads the file and cannot know who wrote it"
        ),
        severity=Severity.HIGH if passive else Severity.MEDIUM,
        # The file as it sits on this machine, like every other host row; the
        # evidence keeps the path relative, which is what an operator greps.
        target=str(root / repo.path / key.origin),
        tags=["host", "host.git_exec"],
        evidence={
            "repository": repo.path,
            "role": repo.role,
            "key": key.key,
            "scope": _scope(key),
            "origin": key.origin,
            "reached_by": reached_by,
            "passive": passive,
            "value_form": key.shape.form,
            "value_length": key.shape.length,
            "value_references": list(key.shape.references),
            "scope_rule": _GIT_SCOPE_RULE,
        },
    )


def _gap_row(root: Path, repo: GitRepoDir) -> Finding:
    """Configuration this audit could not read, named as such.

    A repository whose config did not parse is one whose executable keys are
    unknown, and reporting it with a shorter key list would present it as
    clean (R-2.1). The bound is ours, not the machine's, which is why this
    carries no lens.
    """
    return Finding(
        module="host.enumeration_gap",
        title=f"{repo.path}: git configuration partly unread",
        detail=(
            f"{repo.path} declares git configuration this reader could not interpret at "
            f"{len(repo.gaps)} location(s): {'; '.join(repo.gaps)}. The keys reported for this "
            "repository are the readable ones, so it is partly unassessed rather than read clean"
        ),
        severity=Severity.MEDIUM,
        target=str(root / repo.path),
        tags=["host", "host.enumeration_gap"],
        evidence={"repository": repo.path, "role": repo.role, "unread": list(repo.gaps)},
    )


def _walk_gap_row(root: Path, surface: GitSurface) -> Finding:
    """What the tree walk itself did not cover (R-2.5).

    Every entry here is a bound of this scanner - a pruned subtree, a directory
    it could not list, the walk budget - so the row says so in as many words
    rather than letting the result imply the tree was examined whole.
    """
    return Finding(
        module="host.enumeration_gap",
        title=f"git repository search covered {surface.dirs_walked} directory/ies with gaps",
        detail=(
            f"The search for git repository directories walked {surface.dirs_walked} directory/ies and "
            f"left {len(surface.gaps)} place(s) unexamined: {'; '.join(surface.gaps)}. These are bounds "
            "of this scanner rather than facts about the tree, so a repository under one of them would "
            "not appear above"
        ),
        severity=Severity.MEDIUM,
        target=str(root),
        tags=["host", "host.enumeration_gap"],
        evidence={"dirs_walked": surface.dirs_walked, "unexamined": list(surface.gaps)},
    )


def git_exec_findings(surface: GitSurface, project_root: Path) -> list[Finding]:
    """Rows for every configuration key measured to run a program, plus the gaps.

    A key whose value is a git boolean is skipped: it selects built-in
    behaviour and runs nothing, which is the measured half of R-2.4 for this
    detector. A key not in the table is skipped for the other half - this
    reports execution paths, not every key a repository happens to set.
    """
    out: list[Finding] = []
    for repo in surface.repos:
        for key in repo.keys:
            entry = _EXECUTABLE_KEYS.get(key.pattern)
            if entry is None or key.boolean is not None:
                continue
            reached_by, passive = entry
            out.append(_row(project_root, repo, key, reached_by, passive))
        if repo.gaps:
            out.append(_gap_row(project_root, repo))
    if surface.gaps:
        out.append(_walk_gap_row(project_root, surface))
    return out
