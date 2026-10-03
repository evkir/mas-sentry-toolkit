# SPDX-License-Identifier: AGPL-3.0-or-later
"""Judging the config file itself: who can change it, and whether it is where it looks.

The exposure is built directly here rather than through a real tree. The cases
that matter include an owner other than the one running the audit and a sticky
directory, and constructing the facts is the only way to cover them without
needing a second account or a 1777 directory somebody else owns.

The silent cases carry their own tests, because what this module refuses to say
is half of what it is for: group-writability, a sticky directory, an owner
mismatch and unreadable permissions each have to produce nothing (R-2.4).
"""

from __future__ import annotations

from pathlib import Path

from mas_sentry.core.finding import Severity
from mas_sentry.host import HostConfig, PathExposure, integrity_findings


def _config(
    *,
    mode: int | None = 0o644,
    dir_mode: int = 0o755,
    owned_by_auditor: bool = True,
    via_symlink: bool = False,
    scope: str = "user",
) -> HostConfig:
    """One located config. `mode=None` means the permissions could not be read."""
    exposure = None if mode is None else PathExposure(mode=mode, dir_mode=dir_mode, owned_by_auditor=owned_by_auditor)
    return HostConfig(
        host="claude-code",
        scope=scope,  # type: ignore[arg-type]
        kind="executable",  # type: ignore[arg-type]
        path=Path("/home/op/.claude/settings.json"),
        exists=True,
        resolved=Path("/elsewhere/settings.json" if via_symlink else "/home/op/.claude/settings.json"),
        via_symlink=via_symlink,
        note="user-scope settings",
        exposure=exposure,
    )


def _modules(config: HostConfig) -> list[str]:
    return [f.module for f in integrity_findings(config)]


def test_a_world_writable_file_is_reported_as_the_file_route() -> None:
    rows = integrity_findings(_config(mode=0o666))
    assert [f.module for f in rows] == ["host.config_writable"]
    assert rows[0].evidence["routes"] == ["file"]
    assert rows[0].severity is Severity.HIGH


def test_a_restrictive_file_in_a_world_writable_directory_is_still_reported() -> None:
    """The case a file-only reader would call clean.

    POSIX makes replacing a file a property of the directory, so 0644 inside
    0777 is fully replaceable and the row has to name the directory as the
    route rather than the mode of the file.
    """
    rows = integrity_findings(_config(mode=0o644, dir_mode=0o777))
    assert [f.module for f in rows] == ["host.config_writable"]
    assert rows[0].evidence["routes"] == ["directory"]
    assert "0777" in rows[0].detail


def test_both_routes_open_are_reported_as_both() -> None:
    rows = integrity_findings(_config(mode=0o666, dir_mode=0o777))
    assert rows[0].evidence["routes"] == ["file", "directory"]


def test_a_sticky_world_writable_directory_is_silent() -> None:
    """`/tmp` is 1777 and nobody can replace another user's file in it."""
    assert _modules(_config(mode=0o644, dir_mode=0o1777)) == []


def test_a_group_writable_file_is_silent() -> None:
    """Whether the group reaches anybody else is undocumented, so nothing is claimed."""
    assert _modules(_config(mode=0o664, dir_mode=0o775)) == []


def test_an_owner_other_than_the_auditor_is_not_by_itself_a_finding() -> None:
    """`--home` points at other accounts and mounted images by design."""
    assert _modules(_config(mode=0o600, owned_by_auditor=False)) == []


def test_permissions_that_could_not_be_read_produce_no_verdict() -> None:
    """Windows, a broken link, a directory that cannot be traversed."""
    assert _modules(_config(mode=None)) == []


def test_a_clean_config_is_silent() -> None:
    assert _modules(_config(mode=0o600, dir_mode=0o700)) == []


def test_a_redirected_path_is_its_own_row_with_both_paths() -> None:
    rows = integrity_findings(_config(via_symlink=True))
    assert [f.module for f in rows] == ["host.config_redirected"]
    assert rows[0].evidence["declared_path"].endswith(".claude/settings.json")
    assert rows[0].evidence["resolved_path"] == "/elsewhere/settings.json"


def test_redirection_is_graded_by_who_chose_the_destination() -> None:
    """A dotfile manager symlinks the operator's own config; a repository does not."""
    user = integrity_findings(_config(via_symlink=True, scope="user"))
    assert user[0].severity is Severity.LOW
    project = integrity_findings(_config(via_symlink=True, scope="project"))
    assert project[0].severity is Severity.MEDIUM


def test_a_path_that_is_where_it_looks_produces_no_redirection_row() -> None:
    assert "host.config_redirected" not in _modules(_config())


def test_the_two_rows_are_independent() -> None:
    """A redirected config that is also writable gets both, not one standing in for the other."""
    assert _modules(_config(mode=0o666, via_symlink=True)) == [
        "host.config_writable",
        "host.config_redirected",
    ]
