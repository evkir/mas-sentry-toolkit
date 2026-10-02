# SPDX-License-Identifier: AGPL-3.0-or-later
"""Comparing server declarations across scopes by name.

Precedence is local, then project, then user, and the winning entry is taken
whole rather than merged (https://code.claude.com/docs/en/mcp). So a repository
`.mcp.json` that reuses a user-scope server name decides what runs. These cases
drive the real locator and reader, so the pairing is tested against the shapes
discovery actually produces.
"""

from __future__ import annotations

import json
from pathlib import Path

from mas_sentry.core.finding import Severity
from mas_sentry.host import cross_scope_findings, locate, read

_USER_TOKEN = "ghp_user_scope_token_0123456789"


def _inventories(tmp_path: Path, *, user: dict | None = None, project: dict | None = None) -> list:
    """Write a user `.claude.json` and a project `.mcp.json`, read both."""
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    home.mkdir(parents=True, exist_ok=True)
    repo.mkdir(parents=True, exist_ok=True)
    if user is not None:
        (home / ".claude.json").write_text(json.dumps(user))
    if project is not None:
        (repo / ".mcp.json").write_text(json.dumps(project))
    configs = locate(home=home, project_root=repo, system="Linux")
    return [read(c) for c in configs if c.exists]


def _srv(**fields) -> dict:
    return fields


# --- the override case ------------------------------------------------------


def test_a_repository_server_reusing_a_user_name_is_high(tmp_path: Path) -> None:
    findings = cross_scope_findings(
        _inventories(
            tmp_path,
            user={"mcpServers": {"git": _srv(command="uvx", args=["mcp-server-git"])}},
            project={"mcpServers": {"git": _srv(command="node", args=["./shim.js"])}},
        )
    )
    (f,) = findings
    assert f.module == "host.server_override"
    assert f.severity == Severity.HIGH
    assert f.evidence["server"] == "git"
    assert f.evidence["changed_fields"] == ["command", "args"]


def test_both_sides_of_the_change_reach_the_evidence(tmp_path: Path) -> None:
    """A verdict a reviewer cannot re-derive is not deterministic (R-7.2)."""
    (f,) = cross_scope_findings(
        _inventories(
            tmp_path,
            user={"mcpServers": {"git": _srv(command="uvx", env={"GH_TOKEN": _USER_TOKEN})}},
            project={"mcpServers": {"git": _srv(command="node", env={"GH_TOKEN": "${GH_TOKEN}"})}},
        )
    )
    assert f.evidence["wins"]["scope"] == "project"
    assert f.evidence["wins"]["command"] == "node"
    assert f.evidence["overridden"]["scope"] == "user"
    assert f.evidence["overridden"]["command"] == "uvx"
    # The forms are kept on both sides; neither value is.
    assert f.evidence["wins"]["env_forms"] == {"GH_TOKEN": "reference"}
    assert f.evidence["overridden"]["env_forms"] == {"GH_TOKEN": "literal"}
    assert _USER_TOKEN not in repr(f)


def test_a_url_swapped_for_a_command_is_named_as_changed(tmp_path: Path) -> None:
    (f,) = cross_scope_findings(
        _inventories(
            tmp_path,
            user={"mcpServers": {"api": _srv(type="http", url="https://internal.test/mcp")}},
            project={"mcpServers": {"api": _srv(type="stdio", command="node", args=["x.js"])}},
        )
    )
    assert set(f.evidence["changed_fields"]) == {"declared_type", "command", "args", "url"}


def test_an_env_only_change_still_counts(tmp_path: Path) -> None:
    """Swapping which variables a launch receives changes the launch."""
    (f,) = cross_scope_findings(
        _inventories(
            tmp_path,
            user={"mcpServers": {"git": _srv(command="uvx")}},
            project={"mcpServers": {"git": _srv(command="uvx", env={"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}"})}},
        )
    )
    assert f.evidence["changed_fields"] == ["env"]


# --- the local-scope bound --------------------------------------------------


def test_an_unread_local_scope_is_stated_in_the_finding(tmp_path: Path) -> None:
    """Local scope outranks project scope, so an unread one bounds the verdict."""
    (f,) = cross_scope_findings(
        _inventories(
            tmp_path,
            user={"mcpServers": {"git": _srv(command="uvx")}, "projects": {"/x": {"mcpServers": {}}}},
            project={"mcpServers": {"git": _srv(command="node")}},
        )
    )
    assert f.evidence["local_scope_unread"] is True
    assert "Local scope outranks project scope" in f.detail


def test_without_a_projects_key_the_bound_is_not_claimed(tmp_path: Path) -> None:
    (f,) = cross_scope_findings(
        _inventories(
            tmp_path,
            user={"mcpServers": {"git": _srv(command="uvx")}},
            project={"mcpServers": {"git": _srv(command="node")}},
        )
    )
    assert f.evidence["local_scope_unread"] is False
    assert "Local scope outranks" not in f.detail


# --- quiet cases ------------------------------------------------------------


def test_an_identical_redeclaration_raises_nothing(tmp_path: Path) -> None:
    """It takes precedence, but it launches what the operator already had (R-2.4)."""
    same = _srv(command="node", args=["s.js"], env={"A": "${A}"})
    assert (
        cross_scope_findings(
            _inventories(tmp_path, user={"mcpServers": {"s": same}}, project={"mcpServers": {"s": dict(same)}})
        )
        == []
    )


def test_a_name_only_in_the_repository_raises_nothing(tmp_path: Path) -> None:
    """A new server is inventory, not an override; c4 judges how it is pinned."""
    assert (
        cross_scope_findings(
            _inventories(
                tmp_path,
                user={"mcpServers": {"git": _srv(command="uvx")}},
                project={"mcpServers": {"brand-new": _srv(command="npx", args=["-y", "pkg"])}},
            )
        )
        == []
    )


def test_a_name_only_in_user_scope_raises_nothing(tmp_path: Path) -> None:
    assert cross_scope_findings(_inventories(tmp_path, user={"mcpServers": {"git": _srv(command="uvx")}})) == []


def test_no_configs_at_all_is_quiet(tmp_path: Path) -> None:
    assert cross_scope_findings(_inventories(tmp_path)) == []


# --- several declarations ---------------------------------------------------


def test_each_overridden_name_gets_its_own_row(tmp_path: Path) -> None:
    findings = cross_scope_findings(
        _inventories(
            tmp_path,
            user={"mcpServers": {"a": _srv(command="uvx"), "b": _srv(command="uvx"), "c": _srv(command="uvx")}},
            project={"mcpServers": {"a": _srv(command="node"), "b": _srv(command="deno"), "c": _srv(command="uvx")}},
        )
    )
    assert sorted(f.evidence["server"] for f in findings) == ["a", "b"]
