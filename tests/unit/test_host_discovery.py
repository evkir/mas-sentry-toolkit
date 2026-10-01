# SPDX-License-Identifier: AGPL-3.0-or-later
"""Host-config discovery against real directory trees.

Every case below builds actual files and actual symlinks under tmp_path rather
than patching `Path.exists` or `platform.system`. A patched filesystem agrees
with whatever the test asserts; a real one does not, and the symlink cases in
particular only mean something against a real link.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mas_sentry.host import HostConfig, locate, present, supported_hosts


def _by(
    configs: list[HostConfig],
    host: str,
    scope: str,
    kind: str = "mcp_servers",
    name: str | None = None,
) -> HostConfig:
    """Select one located config.

    (host, scope, kind) is deliberately not a unique key: Claude Code reads both
    `settings.json` and `settings.local.json` from a repository, and collapsing
    them would mean the table could only ever describe one settings file per
    host. `name` disambiguates by filename where a host has more than one.
    """
    matches = [c for c in configs if c.host == host and c.scope == scope and c.kind == kind]
    if name is not None:
        matches = [c for c in matches if c.path.name == name]
    assert len(matches) == 1, f"expected exactly one {host}/{scope}/{kind}/{name}, got {len(matches)}"
    return matches[0]


def test_supported_hosts_are_unique_and_ordered() -> None:
    hosts = supported_hosts()
    assert len(hosts) == len(set(hosts))
    assert "claude-code" in hosts
    assert "cursor" in hosts
    assert "windsurf" in hosts


@pytest.mark.parametrize(
    ("system", "expected_tail"),
    [
        ("Darwin", ("Library", "Application Support", "Claude", "claude_desktop_config.json")),
        ("Linux", (".config", "Claude", "claude_desktop_config.json")),
    ],
)
def test_claude_desktop_path_follows_the_platform(tmp_path: Path, system: str, expected_tail: tuple[str, ...]) -> None:
    home = tmp_path / "home"
    home.mkdir()
    configs = locate(home=home, project_root=tmp_path / "repo", system=system)
    desktop = _by(configs, "claude-desktop", "user")
    assert desktop.path == home.joinpath(*expected_tail)


def test_windows_user_scope_anchors_to_appdata(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    configs = locate(home=home, project_root=tmp_path / "repo", system="Windows")

    # Claude Desktop lives under %APPDATA% on Windows...
    desktop = _by(configs, "claude-desktop", "user")
    assert desktop.path == home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"

    # ...while Claude Code keeps a dotfile in the home directory on every platform.
    code = _by(configs, "claude-code", "user")
    assert code.path == home / ".claude.json"


def test_explicit_appdata_overrides_the_default(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    roaming = tmp_path / "elsewhere" / "Roaming"
    configs = locate(home=home, project_root=tmp_path / "repo", system="Windows", appdata=roaming)
    assert _by(configs, "claude-desktop", "user").path == roaming / "Claude" / "claude_desktop_config.json"


def test_project_scope_anchors_to_the_repository(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    configs = locate(home=tmp_path / "home", project_root=repo, system="Linux")
    assert _by(configs, "portable", "project").path == repo / ".mcp.json"
    assert _by(configs, "cursor", "project").path == repo / ".cursor" / "mcp.json"
    assert (
        _by(configs, "claude-code", "project", "settings", "settings.json").path == repo / ".claude" / "settings.json"
    )
    assert (
        _by(configs, "claude-code", "project", "settings", "settings.local.json").path
        == repo / ".claude" / "settings.local.json"
    )


def test_one_host_may_declare_several_files_of_the_same_kind(tmp_path: Path) -> None:
    """A host is not limited to one file per kind, and the table must not assume it is.

    Claude Code reads committed repository settings and a local override from
    separate files, and the two carry different trust: one arrives with the
    checkout, the other does not. Keying the inventory on (host, scope, kind)
    would silently keep whichever came last.
    """
    repo = tmp_path / "repo"
    configs = locate(home=tmp_path / "home", project_root=repo, system="Linux")
    settings = [c for c in configs if c.host == "claude-code" and c.scope == "project" and c.kind == "settings"]
    assert {c.path.name for c in settings} == {"settings.json", "settings.local.json"}
    assert len({c.path for c in configs}) == len(configs), "no path may be located twice"


def test_absent_config_is_reported_not_dropped(tmp_path: Path) -> None:
    """A host the operator does not run still produces a row.

    An empty list would read as "nothing to assess", which is the one thing the
    report must never say about a surface it did not examine.
    """
    configs = locate(home=tmp_path / "home", project_root=tmp_path / "repo", system="Linux")
    assert configs, "the Linux table must not be empty"
    assert all(c.exists is False for c in configs)
    assert present(configs) == []


def test_existing_config_is_marked_present(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text("{}")

    configs = locate(home=home, project_root=tmp_path / "repo", system="Linux")
    cursor = _by(configs, "cursor", "user")
    assert cursor.exists is True
    assert [c.path for c in present(configs)] == [cursor.path]


def test_every_entry_carries_the_reason_it_was_examined(tmp_path: Path) -> None:
    configs = locate(home=tmp_path / "home", project_root=tmp_path / "repo", system="Darwin")
    assert all(c.note for c in configs), "a located path with no stated reason is not auditable"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlinked_config_directory_is_flagged(tmp_path: Path) -> None:
    """A config reached through a link inside the operator's tree is the CVE-2026-50549 shape."""
    home = tmp_path / "home"
    home.mkdir()
    elsewhere = tmp_path / "attacker"
    elsewhere.mkdir()
    (elsewhere / "mcp.json").write_text("{}")
    (home / ".cursor").symlink_to(elsewhere, target_is_directory=True)

    cursor = _by(locate(home=home, project_root=tmp_path / "repo", system="Linux"), "cursor", "user")
    assert cursor.exists is True
    assert cursor.via_symlink is True
    assert cursor.resolved == elsewhere.resolve() / "mcp.json"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlinked_home_is_not_flagged(tmp_path: Path) -> None:
    """The guard that keeps the check from firing on every path it sees.

    A home directory that is itself a link is ordinary - a home on a mounted
    volume, or anything under /tmp on macOS. If the anchor counted, every
    config under such a home would report as redirected and the real case would
    be indistinguishable from the noise.
    """
    real_home = tmp_path / "volume" / "alice"
    (real_home / ".cursor").mkdir(parents=True)
    (real_home / ".cursor" / "mcp.json").write_text("{}")
    linked_home = tmp_path / "home"
    linked_home.symlink_to(real_home, target_is_directory=True)

    cursor = _by(locate(home=linked_home, project_root=tmp_path / "repo", system="Linux"), "cursor", "user")
    assert cursor.exists is True
    assert cursor.via_symlink is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics")
def test_a_symlinked_config_file_is_flagged(tmp_path: Path) -> None:
    """The link may be the file itself rather than its directory."""
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    target = tmp_path / "attacker-owned.json"
    target.write_text("{}")
    (home / ".cursor" / "mcp.json").symlink_to(target)

    cursor = _by(locate(home=home, project_root=tmp_path / "repo", system="Linux"), "cursor", "user")
    assert cursor.via_symlink is True
    assert cursor.resolved == target.resolve()


def test_a_platform_without_a_host_emits_no_row_for_it(tmp_path: Path) -> None:
    """Absent from the table is not the same as absent from disk.

    Every spec in the table currently ships on all three platforms, so the
    assertion is that the two sets differ only where the table says they do -
    a Linux run must not inherit the macOS Library path.
    """
    linux = locate(home=tmp_path / "h", project_root=tmp_path / "r", system="Linux")
    darwin = locate(home=tmp_path / "h", project_root=tmp_path / "r", system="Darwin")
    linux_paths = {c.path for c in linux}
    darwin_paths = {c.path for c in darwin}
    assert not any("Application Support" in str(p) for p in linux_paths)
    assert any("Application Support" in str(p) for p in darwin_paths)


def test_an_unknown_platform_yields_nothing(tmp_path: Path) -> None:
    """A platform the table does not describe produces no rows at all.

    Reporting it as "no configs found" would be a clean result for a machine
    that was never examined, so the caller has to be able to tell the two
    apart - an empty list here means the table has nothing to say.
    """
    assert locate(home=tmp_path / "h", project_root=tmp_path / "r", system="SunOS") == []
