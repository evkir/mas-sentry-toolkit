# SPDX-License-Identifier: AGPL-3.0-or-later
"""Locate the agent-host configurations that launch MCP servers.

The 2026 CVE corpus moved a large part of the MCP attack surface off the
scanned server and onto the operator's own machine:

- CVE-2026-21852 - repository settings point the API endpoint elsewhere through
  `env`, and the user's key is sent there before the trust dialog is answered.
- GHSA-ph6w-f82w-28w6, CVE-2025-59536 - code declared in repository settings
  runs on open: by design once the folder is trusted, and before trust through
  the dialog bug fixed in 1.0.111.
- CVE-2025-54136 ("MCPoison") - a config another writer can rewrite after the
  user approved it, which makes the approval persistent for the attacker.
- CVE-2026-50549 ("DuneSlide") - a config path that canonicalises somewhere
  other than where it appears to be.

None of that is observable from the far end of a connection, so it needs its
own entry point rather than a flag on `mcp scan`.

This module locates, reads the permissions of what it located, and nothing
more. It does not open the files: their contents have their own rules about what
may enter a report (a config holds API keys), and a path that was only located
cannot leak one. The read step consumes what this returns.

Permissions are read here because two of the cases above turn on them, and on
two different objects. Rewriting a config in place needs write permission on the
file; replacing it needs write permission on the directory holding it, which
POSIX grants to anyone who can write there unless the sticky bit is set. A
reader that looked only at the file would call a 0644 config in a 0777 directory
clean, which is the MCPoison vector exactly.
https://man7.org/linux/man-pages/man2/unlink.2.html

Paths follow each host's documented location. The project scope matters as much
as the user scope: `.mcp.json` at a repository root is the portable format and
is honoured by more than one host, so a single file committed to a repository is
read by whichever of them the next operator happens to run.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

Scope = Literal["user", "project"]
"""Whether a config belongs to the operator or travels with a repository."""

Kind = Literal["mcp_servers", "settings"]
"""What the file declares.

The distinction is load-bearing downstream: a server inventory and a settings
file carrying hooks are different schemas and different threat classes, and the
reader should not have to guess which one it opened from the filename alone.
"""

Anchor = Literal["home", "appdata", "project"]

_SYSTEMS: Final = ("Darwin", "Linux", "Windows")


@dataclass(frozen=True, slots=True)
class PathExposure:
    """Who, besides the owner, can change the file the host will read.

    `mode` and `dir_mode` are the permission bits of the file and of the
    directory holding it, sticky bit included. Both are kept because they are
    two routes to one outcome: writing the file in place needs permission on
    the file, replacing it needs permission on the directory.

    `owned_by_auditor` is False when the file belongs to somebody other than
    the user running the audit. It is a fact rather than an assumption because
    the command takes `--home`: a responder examining a mounted image or another
    account on a shared machine owns none of what it reads.

    No verdict is drawn here. Which combination of bits amounts to an exposure
    depends on the threat, and that belongs to whatever judges these (R-1.7).
    """

    mode: int
    dir_mode: int
    owned_by_auditor: bool


@dataclass(frozen=True, slots=True)
class HostConfig:
    """One located configuration file.

    `exists` is False for a path that is simply absent, which is the normal
    case for a host the operator has not installed. It is reported rather than
    dropped so a caller can tell "this host declares no config" from "this host
    was never looked for" - the same distinction the scanner draws everywhere
    else between a clean result and an unassessed surface.
    """

    host: str
    scope: Scope
    kind: Kind
    path: Path
    exists: bool
    resolved: Path
    via_symlink: bool
    note: str
    exposure: PathExposure | None = None


@dataclass(frozen=True, slots=True)
class _Location:
    anchor: Anchor
    parts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Spec:
    host: str
    scope: Scope
    kind: Kind
    note: str
    # Keyed by platform.system(). A platform absent from the mapping is a
    # platform where the host does not ship, which is not the same as a config
    # that is missing - the entry is not emitted at all rather than emitted as
    # absent, so a Linux run does not report every macOS path as a gap.
    per_system: Mapping[str, _Location]


def _everywhere(anchor: Anchor, *parts: str) -> Mapping[str, _Location]:
    """One location that is identical on all three platforms."""
    loc = _Location(anchor, parts)
    return dict.fromkeys(_SYSTEMS, loc)


# The host table is data, not control flow: adding a host is one entry, and the
# `note` travels into the report so a reader can tell why a path was examined.
_SPECS: Final[tuple[_Spec, ...]] = (
    _Spec(
        host="claude-code",
        scope="user",
        kind="mcp_servers",
        note="Claude Code user-scope server inventory",
        per_system=_everywhere("home", ".claude.json"),
    ),
    _Spec(
        host="claude-code",
        scope="user",
        kind="settings",
        note="Claude Code user settings; hooks declared here run for every project",
        per_system=_everywhere("home", ".claude", "settings.json"),
    ),
    _Spec(
        host="claude-code",
        scope="project",
        kind="settings",
        note="Repository settings; its hooks and helper commands arrive with the checkout (GHSA-ph6w-f82w-28w6)",
        per_system=_everywhere("project", ".claude", "settings.json"),
    ),
    _Spec(
        host="claude-code",
        scope="project",
        kind="settings",
        note="Repository-local settings override, not usually committed",
        per_system=_everywhere("project", ".claude", "settings.local.json"),
    ),
    _Spec(
        host="portable",
        scope="project",
        kind="mcp_servers",
        note="Portable format at the repository root; honoured by more than one host (CVE-2026-21852)",
        per_system=_everywhere("project", ".mcp.json"),
    ),
    _Spec(
        host="portable",
        scope="user",
        kind="mcp_servers",
        note="Portable format, user scope",
        per_system={
            "Darwin": _Location("home", (".copilot", "mcp-config.json")),
            "Linux": _Location("home", (".copilot", "mcp-config.json")),
            "Windows": _Location("appdata", (".copilot", "mcp-config.json")),
        },
    ),
    _Spec(
        host="claude-desktop",
        scope="user",
        kind="mcp_servers",
        note="Claude Desktop server inventory",
        per_system={
            "Darwin": _Location("home", ("Library", "Application Support", "Claude", "claude_desktop_config.json")),
            "Linux": _Location("home", (".config", "Claude", "claude_desktop_config.json")),
            "Windows": _Location("appdata", ("Claude", "claude_desktop_config.json")),
        },
    ),
    _Spec(
        host="cursor",
        scope="user",
        kind="mcp_servers",
        note="Cursor user-scope server inventory (CVE-2025-54136 rewrites this file)",
        per_system=_everywhere("home", ".cursor", "mcp.json"),
    ),
    _Spec(
        host="cursor",
        scope="project",
        kind="mcp_servers",
        note="Cursor repository-scope server inventory",
        per_system=_everywhere("project", ".cursor", "mcp.json"),
    ),
    _Spec(
        host="windsurf",
        scope="user",
        kind="mcp_servers",
        note="Windsurf server inventory (CVE-2026-30615 launches from this file)",
        per_system=_everywhere("home", ".codeium", "windsurf", "mcp_config.json"),
    ),
    _Spec(
        host="vscode",
        scope="project",
        kind="mcp_servers",
        note="VS Code workspace server inventory, forwarded to the agent host",
        per_system=_everywhere("project", ".vscode", "mcp.json"),
    ),
    _Spec(
        host="vscode",
        scope="user",
        kind="mcp_servers",
        note="VS Code user-profile server inventory",
        per_system={
            "Darwin": _Location("home", ("Library", "Application Support", "Code", "User", "mcp.json")),
            "Linux": _Location("home", (".config", "Code", "User", "mcp.json")),
            "Windows": _Location("appdata", ("Code", "User", "mcp.json")),
        },
    ),
)


def supported_hosts() -> tuple[str, ...]:
    """Host identifiers this module knows how to locate, in table order."""
    seen: dict[str, None] = {}
    for spec in _SPECS:
        seen.setdefault(spec.host, None)
    return tuple(seen)


def _exposure_of(path: Path, system: str) -> PathExposure | None:
    """Permission facts for the file a host will read, or None when there are none.

    The resolved path is what gets examined, not the declared one: the mode that
    decides whether the content can be rewritten belongs to the file the link
    arrives at. That a link was followed at all is already carried separately,
    so nothing about the redirection is lost by looking through it.

    Windows is excluded rather than described. `os.stat` there synthesises POSIX
    mode bits from the read-only attribute and reports no owner, so a verdict
    drawn from them would be about the emulation rather than about the ACL that
    governs the file. An unknown is marked unknown instead of guessed (R-2.5).
    """
    if system == "Windows":
        return None
    try:
        info = path.stat()
        holder = path.parent.stat()
    except OSError:
        # A broken link, a directory that cannot be traversed, a file removed
        # between locating and reading it. The absence is reported by returning
        # None; it is not an audit failure, and it is not a clean result either.
        return None
    return PathExposure(
        mode=stat.S_IMODE(info.st_mode),
        dir_mode=stat.S_IMODE(holder.st_mode),
        owned_by_auditor=info.st_uid == os.getuid(),
    )


def _anchor_path(anchor: Anchor, home: Path, project_root: Path, appdata: Path) -> Path:
    if anchor == "home":
        return home
    if anchor == "appdata":
        return appdata
    return project_root


def _default_appdata(home: Path, system: str) -> Path:
    """Where %APPDATA% points on a default Windows install.

    Only consulted when the caller does not pass one. On the other two
    platforms nothing anchors to it, so the value is never read and its shape
    does not matter.
    """
    if system == "Windows":
        return home / "AppData" / "Roaming"
    return home


def _symlinked(declared: Path, anchor: Path, parts: Sequence[str]) -> tuple[Path, bool]:
    """Canonicalise the declared path and say whether it moved.

    The comparison is against the anchor's own canonical form, not against the
    declared path as written. A home directory that is itself a symlink - the
    default on macOS for anything under /tmp, and common for a home on a
    mounted volume - would otherwise mark every config as redirected and bury
    the one case that matters. What matters is a link *inside* the operator's
    tree pointing the config somewhere else, so the anchor is canonicalised on
    both sides and only the remainder of the path can differ.
    """
    resolved = declared.resolve()
    expected = anchor.resolve().joinpath(*parts)
    return resolved, resolved != expected


def locate(
    home: Path,
    project_root: Path,
    system: str,
    appdata: Path | None = None,
) -> list[HostConfig]:
    """Locate every known agent-host config for one machine and one repository.

    `home`, `project_root` and `system` are arguments rather than reads of the
    live environment so a test can drive a real directory tree, with real
    symlinks, for a platform it is not running on. The alternative is patching
    `platform.system` and `Path.home`, which tests the patch.

    Returns every entry the platform defines, present or absent. Filtering to
    what exists is the caller's decision, because "the operator runs none of
    these hosts" and "the operator runs one with no servers configured" are
    different answers and both are worth reporting.
    """
    resolved_appdata = appdata if appdata is not None else _default_appdata(home, system)
    out: list[HostConfig] = []
    for spec in _SPECS:
        location = spec.per_system.get(system)
        if location is None:
            continue
        anchor = _anchor_path(location.anchor, home, project_root, resolved_appdata)
        declared = anchor.joinpath(*location.parts)
        resolved, via_symlink = _symlinked(declared, anchor, location.parts)
        out.append(
            HostConfig(
                host=spec.host,
                scope=spec.scope,
                kind=spec.kind,
                path=declared,
                exists=declared.exists(),
                resolved=resolved,
                via_symlink=via_symlink,
                note=spec.note,
                exposure=_exposure_of(resolved, system) if declared.exists() else None,
            )
        )
    return out


def present(configs: Iterable[HostConfig]) -> list[HostConfig]:
    """The subset that exists on disk."""
    return [c for c in configs if c.exists]
