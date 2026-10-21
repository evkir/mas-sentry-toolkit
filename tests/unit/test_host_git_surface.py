# SPDX-License-Identifier: AGPL-3.0-or-later
"""The git-configuration reader: what it parses, what it walks, what it refuses.

Every structural fact asserted here was measured against git 2.43.0 before the
reader was written, and the cases are arranged so a later change that breaks
one of those facts fails rather than drifts:

- `HEAD` plus `objects/` plus `refs/` is the whole structural test, and each
  part is load-bearing.
- A submodule leaves a `.git` file, not a directory, so it is not a plant.
- `.git/modules/<name>` is a full repository per submodule, which is why the
  walk must not descend into the project's own git directory.
- `core.fsmonitor = true` is git's built-in monitor and runs no program.
- `include.path` and `includeIf` are honoured from a repository's own config,
  so a key can sit in a file the repository only points at.
- Git aborts over an include depth of 10, so reading deeper judges nothing.
"""

from __future__ import annotations

from pathlib import Path

from mas_sentry.host.git_surface import (
    declared_format_version,
    looks_like_repository,
    parse_config,
    read_git_surface,
)

_HEAD = "ref: refs/heads/main\n"
_LOOSE = f"{'0' * 40}\n"
_PROGRAM = "/opt/evil/run.sh"


def _repo_dir(path: Path, config: str | None = None) -> Path:
    """The three structural parts, and optionally a config."""
    (path / "objects").mkdir(parents=True)
    (path / "refs").mkdir(parents=True)
    (path / "HEAD").write_text(_HEAD, encoding="utf-8")
    if config is not None:
        (path / "config").write_text(config, encoding="utf-8")
    return path


def _project(tmp_path: Path, config: str | None = None) -> Path:
    """A checkout whose own `.git` is a directory, as a delivered one is."""
    root = tmp_path / "repo"
    root.mkdir()
    _repo_dir(root / ".git", config)
    return root


def test_the_structural_test_matches_what_git_requires(tmp_path: Path) -> None:
    """All three parts are required, and nothing else is.

    The negative half is the point: a directory git refuses resolves outward to
    the real checkout and executes nothing, so reporting one would be a false
    positive (R-2.4).
    """
    assert looks_like_repository(_repo_dir(tmp_path / "full"))
    assert looks_like_repository(_repo_dir(tmp_path / "with_config", "[core]\n\tbare = true\n")), (
        "a config file and core.bare are both optional"
    )

    no_head = tmp_path / "no_head"
    (no_head / "objects").mkdir(parents=True)
    (no_head / "refs").mkdir(parents=True)
    assert not looks_like_repository(no_head)

    no_objects = tmp_path / "no_objects"
    (no_objects / "refs").mkdir(parents=True)
    (no_objects / "HEAD").write_text(_HEAD, encoding="utf-8")
    assert not looks_like_repository(no_objects)

    no_refs = tmp_path / "no_refs"
    (no_refs / "objects").mkdir(parents=True)
    (no_refs / "HEAD").write_text(_HEAD, encoding="utf-8")
    assert not looks_like_repository(no_refs)


def test_a_format_version_git_refuses_is_not_a_repository(tmp_path: Path) -> None:
    """Git prints "Expected git repo version <= 1" and uses the directory for nothing."""
    future = _repo_dir(tmp_path / "future", "[core]\n\trepositoryformatversion = 99\n")
    assert declared_format_version(future) == 99
    assert not looks_like_repository(future)

    known = _repo_dir(tmp_path / "known", "[core]\n\trepositoryformatversion = 1\n")
    assert looks_like_repository(known)
    assert declared_format_version(_repo_dir(tmp_path / "absent")) == 0, "an absent key reads as 0"
    assert declared_format_version(_repo_dir(tmp_path / "junk", "[core]\n\trepositoryformatversion = x\n")) == 0, (
        "a value that is not an integer is git's to refuse, not ours to guess at"
    )


def test_a_key_is_named_the_way_git_names_it(tmp_path: Path) -> None:
    """Section and name fold case, a subsection does not, and it may hold a space.

    `git config --list` prints `filter.lfs smudge.clean` for this file, so the
    pattern has to reach `filter.*.clean` regardless of what sits in the middle
    - a split of the full name on dots would not.
    """
    keys, includes, gaps = parse_config(
        '[CORE]\n\tFSMonitor = /one\n[filter "lfs smudge"]\n\tclean = /two\n',
        "config",
    )
    assert gaps == []
    assert includes == []
    by_pattern = {k.pattern: k for k in keys}
    assert by_pattern["core.fsmonitor"].key == "core.fsmonitor"
    assert by_pattern["filter.*.clean"].key == "filter.lfs smudge.clean"
    assert by_pattern["filter.*.clean"].subsection == "lfs smudge"


def test_the_legacy_section_spelling_is_read(tmp_path: Path) -> None:
    """`[section.subsection]` without quotes, which git still accepts."""
    keys, _, gaps = parse_config("[filter.mine]\n\tsmudge = /one\n", "config")
    assert gaps == []
    assert [(k.section, k.subsection, k.name) for k in keys] == [("filter", "mine", "smudge")]


def test_comments_quotes_and_continuations_are_read_as_git_reads_them(tmp_path: Path) -> None:
    body = (
        "# a comment\n"
        "; another\n"
        "[core]\n"
        "\tfsmonitor = /one/two # trailing comment\n"
        '\teditor = "/one/with spaces"\n'
        "\tpager = /long/\\\n"
        "path\n"
    )
    keys, _, gaps = parse_config(body, "config")
    assert gaps == []
    shapes = {k.name: k.shape for k in keys}
    # The lengths are what the reader keeps instead of the values, so they are
    # how the parse is checked without the test knowing the text either.
    assert shapes["fsmonitor"].length == len("/one/two")
    assert shapes["editor"].length == len("/one/with spaces")
    assert shapes["pager"].length == len("/long/path")


def test_a_line_that_cannot_be_read_becomes_a_gap(tmp_path: Path) -> None:
    """R-2.1 for the parser: an unread line is stated, never skipped.

    A parser that dropped these quietly would report a repository with no
    executable keys, which is the silent-loss class rather than a clean tree.
    """
    keys, _, gaps = parse_config(
        '[core\n\tfsmonitor = /one\nstray = /two\n[core]\n\teditor = "unclosed\n\tpager = /three\\q\n',
        "config",
    )
    assert [k.key for k in keys] == [], "not one of these five lines is understood, so none may be reported as read"
    assert gaps == [
        "config:1: section header not understood",
        "config:2: key outside any section",
        "config:3: key outside any section",
        "config:5: value quoting not understood",
        "config:6: value quoting not understood",
    ], "every unread line is named with its own number, so an operator can open the file at it"


def test_a_boolean_value_is_recorded_as_one(tmp_path: Path) -> None:
    """`core.fsmonitor = true` is git's built-in monitor: measured, runs nothing.

    The reader has to keep this apart from a path, because a detector that
    reported it would fire on every repository using the built-in monitor
    (R-2.4). Every spelling git accepts, including the empty value.
    """
    body = (
        "[core]\n"
        "\tfsmonitor = true\n"
        "\thooksPath = /real/path\n"
        "[a]\n\tb = yes\n\tc = On\n\td = 1\n\te\n\tf = false\n\tg = OFF\n\th = 0\n"
    )
    keys, _, gaps = parse_config(body, "config")
    assert gaps == []
    booleans = {k.key: k.boolean for k in keys}
    assert booleans["core.fsmonitor"] is True
    assert booleans["core.hookspath"] is None, "a path is not a boolean"
    assert [booleans[f"a.{n}"] for n in "bcde"] == [True, True, True, True]
    assert [booleans[f"a.{n}"] for n in "fgh"] == [False, False, False]


def test_no_config_value_reaches_the_reader_output(tmp_path: Path) -> None:
    """R-7.3 in the type rather than in a filter: there is nowhere to put a value.

    Asserted over the whole surface, not the parser alone, because the
    guarantee has to hold for what a report is built from.

    The credential label is deliberately not asserted. `classify` matches a
    documented prefix at the start of a value, and a git config value is a
    command line with the token somewhere inside it, so the label is `None`
    here. That bound is the same one `surface.py` has for hook commands, and
    widening it would change what every one of those rows says - not something
    to slip into this reader.
    """
    token = "ghp_aBcDeFgHiJkLmNoPqRsT012345678901"
    root = _project(tmp_path, f"[core]\n\tfsmonitor = /opt/sync --key {token}\n")
    surface = read_git_surface(root)
    assert token not in repr(surface)
    (key,) = [k for k in surface.repos[0].keys if k.pattern == "core.fsmonitor"]
    # What survives instead: the shape, which is what a detector reasons about
    # without the characters (R-7.2).
    assert key.shape.form == "literal"
    assert key.shape.length == len(f"/opt/sync --key {token}")


def test_an_include_pulls_a_key_the_config_does_not_hold(tmp_path: Path) -> None:
    """Measured: `include.path` and `includeIf` are honoured from a repository config.

    A reader that stopped at the one file would report a clean repository whose
    `git status` runs a program (R-2.1). The included file is also named, so an
    operator sees that the repository reaches outside itself.
    """
    side = tmp_path / "side.cfg"
    side.write_text(f"[core]\n\tfsmonitor = {_PROGRAM}\n", encoding="utf-8")
    deeper = tmp_path / "deeper.cfg"
    deeper.write_text(f"[core]\n\thooksPath = {_PROGRAM}\n", encoding="utf-8")
    root = _project(
        tmp_path,
        f'[include]\n\tpath = {side}\n[includeIf "gitdir:/anywhere/"]\n\tpath = {deeper}\n',
    )
    (repo,) = read_git_surface(root).repos
    patterns = {k.pattern for k in repo.keys}
    assert "core.fsmonitor" in patterns, "include.path must be followed"
    assert "core.hookspath" in patterns, "includeIf must be followed"
    assert {k.origin for k in repo.keys} == {str(side), str(deeper)}, "a key names the file it came from"
    assert set(repo.includes) == {str(side), str(deeper)}


def test_a_relative_include_resolves_against_the_including_file(tmp_path: Path) -> None:
    root = _project(tmp_path, "[include]\n\tpath = extra.cfg\n")
    (root / ".git" / "extra.cfg").write_text(f"[core]\n\teditor = {_PROGRAM}\n", encoding="utf-8")
    (repo,) = read_git_surface(root).repos
    assert {k.pattern for k in repo.keys} == {"core.editor"}


def test_an_include_cycle_is_bounded_and_stated(tmp_path: Path) -> None:
    """Two files pointing at each other must end the walk, not the process."""
    first = tmp_path / "a.cfg"
    second = tmp_path / "b.cfg"
    first.write_text(f"[include]\n\tpath = {second}\n", encoding="utf-8")
    second.write_text(f"[include]\n\tpath = {first}\n[core]\n\tpager = {_PROGRAM}\n", encoding="utf-8")
    root = _project(tmp_path, f"[include]\n\tpath = {first}\n")
    (repo,) = read_git_surface(root).repos
    assert {k.pattern for k in repo.keys} == {"core.pager"}
    assert any("cycle" in gap for gap in repo.gaps)


def test_an_include_chain_deeper_than_git_allows_is_stated(tmp_path: Path) -> None:
    """Measured: at eleven git aborts, and the repository stops working at all.

    Reading further would mean judging configuration git never applies, so the
    reader stops where git does and says so.
    """
    for index in range(13):
        nxt = tmp_path / f"c{index + 1}.cfg"
        body = f"[include]\n\tpath = {nxt}\n" if index < 12 else f"[core]\n\tpager = {_PROGRAM}\n"
        (tmp_path / f"c{index}.cfg").write_text(body, encoding="utf-8")
    root = _project(tmp_path, f"[include]\n\tpath = {tmp_path / 'c0.cfg'}\n")
    (repo,) = read_git_surface(root).repos
    assert {k.pattern for k in repo.keys} == set(), "the key past git's limit is not reported as applying"
    assert any("include depth over 10" in gap for gap in repo.gaps)


def test_a_planted_repository_is_found_and_the_project_is_labelled(tmp_path: Path) -> None:
    """The delivery that survives a clone, alongside the one that does not."""
    root = _project(tmp_path, f"[core]\n\tfsmonitor = {_PROGRAM}\n")
    (root / "src").mkdir()
    _repo_dir(root / "vendor" / "thing", f"[alias]\n\tll = !{_PROGRAM}\n")
    surface = read_git_surface(root)
    by_role = {r.role: r for r in surface.repos}
    assert by_role["project"].path == ".git"
    assert by_role["plant"].path == "vendor/thing"
    # The alias name is the writer's choice, so the key reads as `alias.ll`.
    # Collapsing that to a table entry is the detector's job, not the reader's.
    assert {k.key for k in by_role["plant"].keys} == {"alias.ll"}
    assert {k.pattern for k in by_role["project"].keys} == {"core.fsmonitor"}
    assert surface.dirs_walked > 0, "an empty result must be distinguishable from a walk that never ran"


def test_a_submodule_is_not_reported_as_a_plant(tmp_path: Path) -> None:
    """Measured: a submodule leaves a `.git` file holding `gitdir:`, not a directory.

    And the repository it points at lives under the project's own
    `.git/modules/<name>`, which satisfies the structural test - so the walk
    skipping the project git directory is what keeps every submodule out of the
    report (R-2.4).
    """
    root = _project(tmp_path)
    kid = root / "vendor" / "kid"
    kid.mkdir(parents=True)
    (kid / ".git").write_text("gitdir: ../../.git/modules/vendor/kid\n", encoding="utf-8")
    _repo_dir(root / ".git" / "modules" / "vendor" / "kid", f"[core]\n\tfsmonitor = {_PROGRAM}\n")
    surface = read_git_surface(root)
    assert [r.role for r in surface.repos] == ["project"], (
        "neither the submodule's .git file nor .git/modules may produce a plant"
    )


def test_a_repository_is_not_descended_into(tmp_path: Path) -> None:
    """One row for the plant, not one per repository nested inside it."""
    root = _project(tmp_path)
    plant = _repo_dir(root / "vendor" / "outer")
    _repo_dir(plant / "modules" / "inner")
    surface = read_git_surface(root)
    assert [r.path for r in surface.repos if r.role == "plant"] == ["vendor/outer"]


def test_a_git_file_at_the_project_root_is_followed_and_noted(tmp_path: Path) -> None:
    """A linked worktree or submodule checkout: the config is not where it appears."""
    root = tmp_path / "repo"
    root.mkdir()
    real = _repo_dir(tmp_path / "elsewhere", f"[core]\n\thooksPath = {_PROGRAM}\n")
    (root / ".git").write_text(f"gitdir: {real}\n", encoding="utf-8")
    surface = read_git_surface(root)
    (repo,) = surface.repos
    assert repo.role == "project"
    assert {k.pattern for k in repo.keys} == {"core.hookspath"}
    assert any("redirects to" in gap for gap in surface.gaps)


def test_a_pruned_directory_is_named_rather_than_silently_skipped(tmp_path: Path) -> None:
    """The walk's own bound, reported as one (R-2.5).

    A plant vendored under `node_modules` is the stated cost of the prune. The
    row says the subtree went unexamined instead of letting the report imply it
    was clean.
    """
    root = _project(tmp_path)
    _repo_dir(root / "node_modules" / "pkg")
    surface = read_git_surface(root)
    assert [r.role for r in surface.repos] == ["project"]
    assert any("node_modules: not descended into" in gap for gap in surface.gaps)


def test_a_symlinked_directory_is_not_followed(tmp_path: Path) -> None:
    """A link can leave the tree the operator asked about, or point at itself."""
    root = _project(tmp_path)
    outside = _repo_dir(tmp_path / "outside")
    (root / "link").symlink_to(outside, target_is_directory=True)
    surface = read_git_surface(root)
    assert [r.role for r in surface.repos] == ["project"]


def test_a_tree_with_no_git_at_all_reports_a_walk_that_happened(tmp_path: Path) -> None:
    """No repository must not look like no audit (R-2.1)."""
    root = tmp_path / "plain"
    (root / "src").mkdir(parents=True)
    surface = read_git_surface(root)
    assert surface.repos == ()
    assert surface.dirs_walked >= 2
    assert surface.gaps == ()


def test_an_unreadable_config_is_a_gap_not_an_empty_key_list(tmp_path: Path) -> None:
    """A directory where the config belongs stands in for a permission denial.

    Without the gap the repository reads as one with no executable keys, which
    is the silent-loss class: the audit would present a configuration it never
    opened as a clean one (R-2.1).
    """
    root = _project(tmp_path)
    (root / ".git" / "config").mkdir()
    (repo,) = read_git_surface(root).repos
    assert repo.keys == ()
    assert repo.gaps == ("config: exists but is not a readable file; its keys were not examined",)


def test_a_repository_with_no_config_at_all_raises_no_gap(tmp_path: Path) -> None:
    """The other half of the one above (R-2.4).

    Git needs no config file, and a plant delivered without one is the common
    case, so an absent file must stay quiet. A gap for every repository that
    simply has nothing to say would bury the unreadable case it exists for.
    """
    root = _project(tmp_path)
    (root / ".git" / "config").unlink(missing_ok=True)
    (repo,) = read_git_surface(root).repos
    assert repo.keys == ()
    assert repo.gaps == ()
