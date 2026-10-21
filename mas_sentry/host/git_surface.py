# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read what a repository's own git configuration makes git execute.

Git calls `system`, `global` and `command` scopes "protected configuration" and
says plainly why the other two are not: `local` ($GIT_DIR/config) and
`worktree` are the repository's own files, which may have arrived with a clone
(https://git-scm.com/docs/git-config, "Protected configuration"). Thirteen keys
in those files were measured to run a program git names there, and the first
two are reached by the commands an agent host runs to orient itself.

Sources:

- GHSA-9ccr-r5hg-74gf / CVE-2026-45033 (GitHub Copilot CLI <= 1.0.42, CWE-696):
  git adopts a repository it finds while walking up, and applies its config.
  Fixed by forcing `safe.bareRepository=explicit` through the environment.
- CVE-2026-19592, CVE-2026-19590, CVE-2026-19593 (OpenAI Codex CLI and
  Desktop): `core.fsmonitor`, `core.hooksPath` and `attr.tree` with a clean or
  process filter, reached by opening a workspace with no trust prompt.
- https://cymulate.com/blog/headless-claude-code-git-config-command-execution/

Everything below about git's own behaviour was measured against git 2.43.0
rather than taken from those write-ups, because each advisory describes its own
product and none of them states the general rule this reader needs.

Two deliveries, and the reader covers both.

A checkout can arrive with its `.git` intact - an archive, a copied folder, a
shared drive - and then `.git/config` is simply read. That file does not
survive `git clone`, which is why the second delivery matters: a directory
holding `HEAD`, an `objects/` directory and a `refs/` directory is a repository
to git wherever it sits and whatever it is called, and git adopts it while
walking up from any command run inside or below it. All three parts are
required and nothing else is: a `config` file, `core.bare`, and any content
under `objects/` or `refs/` are all optional (measured). Since those are
ordinary tracked files, a commit carries them, so this is the shape that
travels through a pull request.

What this module does not do is run git. The first git command in a foreign
checkout is the very class being reported, so the files are parsed instead
(R-7.6). It also judges nothing: which key matters, and how much, is the
detector's question.

No value reaches the caller. A config value here is a command line, and it can
carry a token exactly as a hook command can, so each one is reduced to a shape
before it enters any dataclass a report is built from (R-7.3). The one
exception is the repository format version, which is read as an integer by a
function of its own: it is a structural number that cannot carry a secret, and
it decides whether git would use the directory at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .values import ValueShape, shape_of

# Structural parts a directory needs before git treats it as a repository, each
# one measured as load-bearing: remove any and git refuses the directory and
# resolves outward instead.
_REQUIRED_FILE: Final = "HEAD"
_REQUIRED_DIRS: Final = ("objects", "refs")

# Git refuses a repository whose format version it does not know, printing
# "Expected git repo version <= 1". A directory it refuses executes nothing, so
# it is not reported at all (R-2.4). An absent or unreadable key reads as 0,
# which is the direction to be wrong in: a version git would accept is examined
# rather than skipped.
_MAX_FORMAT_VERSION: Final = 1
_FORMAT_VERSION: Final = re.compile(r"^\s*repositoryformatversion\s*=\s*(\d{1,9})\s*$", re.IGNORECASE | re.MULTILINE)

# Git's own include limit, measured: at eleven it aborts with "exceeded maximum
# include depth (10)" and the repository stops working altogether. Reading
# deeper than git does would mean judging configuration git never applies.
_MAX_INCLUDE_DEPTH: Final = 10

# A config file is operator- or attacker-supplied text. The cap is generous
# next to any real one - the largest in a normal checkout is a few kilobytes -
# and exists so one padded file cannot turn an audit into a memory problem.
_MAX_CONFIG_BYTES: Final = 1_000_000

# Directories visited before the walk gives up and says so. Chosen by budget
# rather than measurement: a checkout with vendored dependencies reaches tens of
# thousands of directories, and no corpus was available to pick a number from.
# Exceeding it is reported as a gap, never as a clean tree (R-2.1).
_MAX_WALK_DIRS: Final = 20_000

# Directories deep enough that walking them costs more than the tree is worth,
# and that can hold a vendored repository: a package installed from a git URL
# brings one. Each skip is named in the gap list, because a repository under
# one of them would not appear in the result (R-2.5).
#
# Tool caches are deliberately NOT here, and the reason was measured rather
# than assumed. This tree carries 553 `__pycache__` directories with zero
# subdirectories in any of them, against 1430 subdirectories ten deep inside
# one `.venv`. Walking a cache is free and the structural test rejects it
# without help - a directory with no subdirectories can hold neither
# `objects/` nor `refs/` - while pruning them produced one gap entry per cache
# and buried the one entry that mattered under thirty that did not. A bound
# reported where there is no bound is the noise R-2.4 forbids.
_PRUNED_DIRS: Final = frozenset({"node_modules", ".venv", "venv", ".tox"})

# `[section "subsection"]`, `[section]`, and the legacy `[section.subsection]`.
_SECTION: Final = re.compile(r'^\[([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\]$')
_KEY: Final = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$")

# Git reads these as booleans, and an empty value is true. A boolean is not a
# program: `core.fsmonitor = true` selects git's own built-in monitor and runs
# nothing, which was measured, so the reader records the distinction and the
# detector does not have to guess at it (R-2.4).
_BOOL_TRUE: Final = frozenset({"true", "yes", "on", "1", ""})
_BOOL_FALSE: Final = frozenset({"false", "no", "off", "0"})

# The two files git reads from inside a repository directory. `config.worktree`
# applies only with the worktreeConfig extension on, and is read regardless:
# whether the extension is set is a detail of a file this reader may not have,
# and a key missed here is a key the audit says nothing about.
_CONFIG_NAMES: Final = ("config", "config.worktree")


def _relative(path: Path, root: Path) -> str:
    """The path as an operator would grep for it, or absolute if it is outside."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


@dataclass(frozen=True, slots=True)
class GitConfigKey:
    """One configuration key, as one file declared it.

    `section` and `name` are lower-cased because git compares them without
    case; `subsection` is kept verbatim because git does not. `pattern` is the
    same key with any subsection collapsed to `*`, which is the form a table of
    keys can be written in: a subsection may hold a space - `git config --list`
    prints `filter.lfs smudge.clean` - so splitting the full name on dots does
    not recover the parts. Which keys matter is the detector's table, not this
    reader's business; it reads every key the file declares.

    `boolean` is `True` or `False` when the value is one of git's boolean
    spellings and `None` otherwise. A boolean names no program.

    `origin` is the file the key was read from. Without it a key pulled in
    through `include.path` would appear to sit in the config itself.
    """

    section: str
    subsection: str
    name: str
    shape: ValueShape
    boolean: bool | None
    origin: str

    @property
    def key(self) -> str:
        """The full name, as `git config --list` prints it."""
        return ".".join(part for part in (self.section, self.subsection, self.name) if part)

    @property
    def pattern(self) -> str:
        """The lookup form, with any subsection collapsed to `*`."""
        return f"{self.section}.*.{self.name}" if self.subsection else f"{self.section}.{self.name}"


@dataclass(frozen=True, slots=True)
class GitRepoDir:
    """One directory git would use as a repository, and what its config says.

    `role` is `project` for the checkout's own git directory and `plant` for
    any other directory in the tree that git would adopt. The two are the same
    class of exposure and a different conversation with the operator: one is
    their repository, the other is something the tree carried in.

    `path` is relative to the project root, which is what an operator greps for
    and what stays the same on another machine. `includes` names every file
    pulled in by `include.path` or `includeIf`, because a key can live in a
    file the repository merely points at - and because a repository pointing at
    a file on the operator's disk is itself worth a row.
    """

    path: str
    role: str
    keys: tuple[GitConfigKey, ...] = ()
    includes: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GitSurface:
    """Every git repository directory reachable from one project root.

    `dirs_walked` is reported so an empty `repos` list can be told from a walk
    that never happened, the same reason the host audit carries `paths_checked`
    (R-2.1). `gaps` holds what the walk could not cover: a denied directory, a
    pruned subtree, the walk budget running out.
    """

    repos: tuple[GitRepoDir, ...] = ()
    dirs_walked: int = 0
    gaps: tuple[str, ...] = ()


def _unquote(raw: str) -> tuple[str, bool]:
    """Strip git's quoting from a value, and say whether it was understood.

    Git drops an inline comment, honours double quotes around any part of the
    value, and recognises four backslash escapes. A backslash before anything
    else is an error in git's own parser, so it is reported rather than guessed
    at: a value this function silently mangled would be judged as if the file
    said something it does not.
    """
    out: list[str] = []
    quoted = False
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == '"':
            quoted = not quoted
        elif char == "\\":
            index += 1
            if index >= len(raw):
                return "".join(out), False
            escape = {'"': '"', "\\": "\\", "n": "\n", "t": "\t", "b": "\b"}.get(raw[index])
            if escape is None:
                return "".join(out), False
            out.append(escape)
        elif char in "#;" and not quoted:
            break
        else:
            out.append(char)
        index += 1
    if quoted:
        return "".join(out), False
    return "".join(out).strip(), True


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """Join continuation lines, keeping the line number the entry started on."""
    out: list[tuple[int, str]] = []
    pending = ""
    start = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not pending:
            start = number
        if line.endswith("\\"):
            pending += line[:-1]
            continue
        out.append((start, pending + line))
        pending = ""
    if pending:
        out.append((start, pending))
    return out


def _section_of(head: str, quoted: str | None) -> tuple[str, str]:
    """Split a section header into its case-folded section and verbatim subsection."""
    if quoted is not None:
        return head.lower(), quoted.replace('\\"', '"').replace("\\\\", "\\")
    if "." in head:
        # The legacy spelling: everything after the first dot is the
        # subsection, and only the section name is case-insensitive.
        section, _, subsection = head.partition(".")
        return section.lower(), subsection
    return head.lower(), ""


def parse_config(text: str, origin: str) -> tuple[list[GitConfigKey], list[str], list[str]]:
    """Parse one git config file into keys, include paths, and what went unread.

    Returns the keys, the raw paths named by `include.path` / `includeIf`, and a
    gap for every line that could not be read. A line this parser skipped
    quietly would be a key the audit reports nothing about, which is the
    silent-loss class (R-2.1), so each one is named with its number.

    Include paths are returned rather than followed here: resolving one needs
    the directory the file sits in, which is the caller's to know.
    """
    keys: list[GitConfigKey] = []
    includes: list[str] = []
    gaps: list[str] = []
    section = ""
    subsection = ""
    for number, raw in _logical_lines(text):
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        if line.startswith("["):
            match = _SECTION.match(line)
            if match is None:
                gaps.append(f"{origin}:{number}: section header not understood")
                continue
            section, subsection = _section_of(match.group(1), match.group(2))
            continue
        entry = _KEY.match(line)
        if entry is None:
            gaps.append(f"{origin}:{number}: entry not understood")
            continue
        if not section:
            gaps.append(f"{origin}:{number}: key outside any section")
            continue
        name = entry.group(1).lower()
        value, understood = _unquote(entry.group(2) or "")
        if not understood:
            gaps.append(f"{origin}:{number}: value quoting not understood")
            continue
        if section in {"include", "includeif"} and name == "path":
            includes.append(value)
            continue
        lowered = value.lower()
        boolean = True if lowered in _BOOL_TRUE else False if lowered in _BOOL_FALSE else None
        keys.append(
            GitConfigKey(
                section=section,
                subsection=subsection,
                name=name,
                shape=shape_of(value),
                boolean=boolean,
                origin=origin,
            )
        )
    return keys, includes, gaps


def _read_text(path: Path) -> tuple[str | None, str | None]:
    """The file's text, or why it could not be had."""
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            return None, f"larger than {_MAX_CONFIG_BYTES} bytes and was not read"
        return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"could not be read: {exc.strerror or exc}"


def declared_format_version(repo_dir: Path) -> int:
    """The repository format version `repo_dir` declares, or 0.

    Read straight out of the text by its own small pattern rather than through
    `parse_config`, because every value that goes through there comes back as a
    shape and a shape has no number in it. The version is a structural integer
    that cannot carry a secret, so reading it is not the thing R-7.3 forbids.

    0 for an absent key, an unreadable file, or a value that is not a plain
    integer: all three are cases where git decides, and treating them as
    "version git accepts" keeps the directory in the audit instead of silently
    dropping it.
    """
    for name in _CONFIG_NAMES:
        text, _ = _read_text(repo_dir / name)
        if text is None:
            continue
        match = _FORMAT_VERSION.search(text)
        if match is not None:
            return int(match.group(1))
    return 0


def looks_like_repository(path: Path) -> bool:
    """Whether git would use `path` as a repository directory.

    The three parts measured as load-bearing, and no more: a `config` file is
    optional, `core.bare` is optional, and `objects/` and `refs/` may both be
    empty. A directory missing any one of the three is refused by git, which
    then resolves outward to the real checkout and executes nothing.

    A format version git does not know is refused the same way, so it fails
    this test too - a directory nothing will ever execute from is not a finding
    waiting to be made (R-2.4).
    """
    structural = (path / _REQUIRED_FILE).is_file() and all((path / name).is_dir() for name in _REQUIRED_DIRS)
    return structural and declared_format_version(path) <= _MAX_FORMAT_VERSION


def _read_chain(start: Path, label: str) -> tuple[list[GitConfigKey], list[str], list[str]]:
    """One config file and everything it includes, to git's own depth limit.

    A relative include resolves against the directory of the file that named
    it, which is what git does. A file already read is not read again: that
    bounds a cycle without needing to count it, and git itself fails outright
    on one.
    """
    keys: list[GitConfigKey] = []
    includes: list[str] = []
    gaps: list[str] = []
    seen: set[Path] = set()
    queue: list[tuple[Path, str, int]] = [(start, label, 0)]
    while queue:
        path, origin, depth = queue.pop(0)
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen:
            gaps.append(f"{origin}: already read; include cycle not followed further")
            continue
        seen.add(resolved)
        if depth > _MAX_INCLUDE_DEPTH:
            gaps.append(f"{origin}: include depth over {_MAX_INCLUDE_DEPTH}, which git refuses outright")
            continue
        if not path.is_file():
            gaps.append(f"{origin}: named by an include but is not a file")
            continue
        text, problem = _read_text(path)
        if text is None:
            gaps.append(f"{origin}: {problem}")
            continue
        found, pointed, trouble = parse_config(text, origin)
        keys.extend(found)
        gaps.extend(trouble)
        for raw in pointed:
            target = Path(raw).expanduser()
            if not target.is_absolute():
                target = path.parent / target
            includes.append(str(target))
            queue.append((target, str(target), depth + 1))
    return keys, includes, gaps


def _repo_at(path: Path, role: str, relative: str) -> GitRepoDir:
    """Read one repository directory's configuration, includes and all."""
    keys: list[GitConfigKey] = []
    includes: list[str] = []
    gaps: list[str] = []
    for name in _CONFIG_NAMES:
        candidate = path / name
        if not candidate.is_file():
            # An absent config is ordinary: git does not need one, and a plant
            # may carry none at all. A path that exists and is not a file is
            # not ordinary - a directory there, or a dangling link, is a
            # configuration this audit did not read, and reporting the
            # repository with an empty key list would present it as clean
            # (R-2.1).
            if candidate.exists() or candidate.is_symlink():
                gaps.append(f"{name}: exists but is not a readable file; its keys were not examined")
            continue
        found, pointed, trouble = _read_chain(candidate, name)
        keys.extend(found)
        includes.extend(pointed)
        gaps.extend(trouble)
    return GitRepoDir(path=relative, role=role, keys=tuple(keys), includes=tuple(includes), gaps=tuple(gaps))


def _project_git_dir(project_root: Path) -> tuple[Path | None, str | None]:
    """The checkout's own git directory, and a note when it is indirected.

    A submodule or a linked worktree has a `.git` file holding `gitdir: <path>`
    instead of a directory. That path is where the config actually lives, so it
    is followed; the note records the redirect, because an operator reading the
    row needs to know the file judged is not the one in the checkout.
    """
    dot = project_root / ".git"
    if dot.is_dir():
        return dot, None
    if not dot.is_file():
        return None, None
    text, problem = _read_text(dot)
    if text is None:
        return None, f".git: {problem}"
    body = text.strip()
    if not body.startswith("gitdir:"):
        return None, ".git is a file but does not name a gitdir"
    target = Path(body[len("gitdir:") :].strip()).expanduser()
    if not target.is_absolute():
        target = project_root / target
    return target, f".git redirects to {_relative(target, project_root)}"


def read_git_surface(project_root: Path) -> GitSurface:
    """Find every git repository directory under `project_root` and read its config.

    The checkout's own git directory is read as the `project` role and then
    excluded from the walk. Excluding it is not tidiness: a repository with
    submodules keeps one full repository per submodule under
    `.git/modules/<name>`, each of which satisfies the structural test, so a
    walk that descended there would report a plant for every submodule (R-2.4).

    A directory that is a repository is not descended into either. Everything
    below it belongs to that repository, and its own `modules/` would read as
    further plants.

    Symbolic links are not followed. A link can point outside the tree the
    operator asked about, and two links can point at each other.
    """
    repos: list[GitRepoDir] = []
    gaps: list[str] = []
    git_dir, note = _project_git_dir(project_root)
    if note is not None:
        gaps.append(note)
    excluded: Path | None = None
    if git_dir is not None and git_dir.is_dir():
        repos.append(_repo_at(git_dir, "project", _relative(git_dir, project_root)))
        try:
            excluded = git_dir.resolve()
        except OSError:
            excluded = git_dir

    walked = 0
    queue: list[Path] = [project_root]
    while queue:
        current = queue.pop(0)
        if walked >= _MAX_WALK_DIRS:
            gaps.append(f"the walk stopped after {_MAX_WALK_DIRS} directories; the rest of the tree is unexamined")
            break
        walked += 1
        try:
            entries = sorted(current.iterdir())
        except OSError as exc:
            gaps.append(f"{_relative(current, project_root)}: not listed: {exc.strerror or exc}")
            continue
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue
            if excluded is not None and _same_dir(entry, excluded):
                continue
            if entry.name in _PRUNED_DIRS:
                gaps.append(f"{_relative(entry, project_root)}: not descended into")
                continue
            if looks_like_repository(entry):
                repos.append(_repo_at(entry, "plant", _relative(entry, project_root)))
                continue
            queue.append(entry)
    return GitSurface(repos=tuple(repos), dirs_walked=walked, gaps=tuple(gaps))


def _same_dir(candidate: Path, resolved: Path) -> bool:
    try:
        return candidate.resolve() == resolved
    except OSError:
        return candidate == resolved
