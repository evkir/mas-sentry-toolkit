# SPDX-License-Identifier: AGPL-3.0-or-later
"""Judging whether a launch spec pins the release it will run.

The two resolvers disagree about syntax, so both are exercised in the forms
their own documentation defines: npx takes a spec positionally or through
`--package`/`-p`, while uvx accepts `pkg@version` for an exact release only and
keeps ranges in `--from`.

Half of what this module is for is staying quiet. An exact pin, a command that
resolves nothing at launch and a remote server each have a test of their own,
because a check an operator cannot pass by doing it right is a false-positive
generator (R-2.4). The finding tests also assert the spec is absent from the
row, the same discipline the credential rows are held to (R-7.3).
"""

from __future__ import annotations

import json
from pathlib import Path

from mas_sentry.core.finding import Severity
from mas_sentry.host import ServerEntry, launch_findings, locate, read, verdict_for


def _entry(command: str | None, *args: str, url: str | None = None) -> ServerEntry:
    return ServerEntry(
        name="s",
        declared_type=None,
        command=command,
        args=args,
        env=(),
        env_file=None,
        cwd=None,
        url=url,
        header_names=(),
        unmodelled=frozenset(),
    )


def _pin(command: str | None, *args: str) -> str | None:
    verdict = verdict_for(_entry(command, *args))
    return None if verdict is None else verdict.pin


def test_an_exact_version_is_silent_in_every_form_the_resolvers_accept() -> None:
    assert _pin("npx", "-y", "pkg@1.2.3") == "exact"
    assert _pin("npx", "-y", "@scope/pkg@1.2.3") == "exact"
    assert _pin("npx", "--package=pkg@1.2.3", "--", "cmd") == "exact"
    assert _pin("npx", "-p", "pkg@1.2.3", "--", "cmd") == "exact"
    assert _pin("uvx", "pkg@1.2.3") == "exact"
    assert _pin("uvx", "--from", "pkg==1.2.3", "cmd") == "exact"
    assert _pin("uvx", "--from=pkg==1.2.3", "cmd") == "exact"
    # A version behind a `v`, which npm and PyPI both accept.
    assert _pin("npx", "-y", "pkg@v2.0.0") == "exact"


def test_a_spec_with_no_version_is_absent() -> None:
    assert _pin("npx", "-y", "some-mcp-server") == "absent"
    assert _pin("uvx", "mcp-server-git") == "absent"
    assert _pin("npx", "-p", "pkg", "--", "cmd") == "absent"
    assert _pin("uvx", "--from", "pkg", "cmd") == "absent"
    # A leading `@` is a scope, not a version separator.
    assert _pin("npx", "-y", "@scope/pkg") == "absent"


def test_a_dist_tag_or_a_range_is_moving() -> None:
    assert _pin("npx", "-y", "pkg@latest") == "moving"
    assert _pin("npx", "-y", "pkg@next") == "moving"
    assert _pin("uvx", "pkg@latest") == "moving"
    assert _pin("uvx", "--from", "pkg>1.0,<2.0", "cmd") == "moving"
    assert _pin("uvx", "--from", "pkg!=1.0", "cmd") == "moving"
    assert _pin("uvx", "--from", "pkg==1.*", "cmd") == "moving"


def test_an_explicit_option_beats_a_positional_spec() -> None:
    """`uvx pkg --from other==1.0` installs `other`, so that is what is judged."""
    assert _pin("uvx", "pkg", "--from", "other==1.0", "cmd") == "exact"


def test_a_command_that_resolves_nothing_at_launch_is_not_judged() -> None:
    for command in ["/usr/local/bin/my-server", "python", "node", "docker", "bash"]:
        assert _pin(command, "whatever") is None, command
    assert _pin(None) is None
    assert verdict_for(_entry(None, url="https://example.test/mcp")) is None
    # A resolver with no arguments names no package to pin.
    assert _pin("npx") is None


def test_the_resolver_is_found_behind_a_path_or_an_extension() -> None:
    assert _pin("/usr/bin/npx", "-y", "pkg") == "absent"
    assert _pin("C:/Program Files/nodejs/npx.exe", "-y", "pkg") == "absent"
    assert _pin("C:\\Program Files\\nodejs\\NPX.EXE", "-y", "pkg") == "absent"


def _inventories(root: Path, rel: str, servers: dict) -> list:
    """Read the inventories of a tree holding one server config at `rel`.

    The relative path is explicit because scope is a property of the location:
    `.mcp.json` at a repository root is the portable project format, while a
    user-scope declaration lives somewhere a host documents under the home
    directory.
    """
    (root / "home").mkdir(parents=True, exist_ok=True)
    (root / "repo").mkdir(parents=True, exist_ok=True)
    config = root / rel
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"mcpServers": servers}))
    configs = locate(home=root / "home", project_root=root / "repo", system="Linux")
    return [read(c) for c in configs if c.exists]


def test_scope_decides_severity_not_truth(tmp_path: Path) -> None:
    loose = {"git": {"command": "uvx", "args": ["mcp-server-git"]}}

    project = _inventories(tmp_path / "p", "repo/.mcp.json", loose)
    rows = [f for inv in project for f in launch_findings(inv)]
    assert [f.severity for f in rows] == [Severity.MEDIUM]

    user = _inventories(tmp_path / "u", "home/.cursor/mcp.json", loose)
    rows = [f for inv in user for f in launch_findings(inv)]
    assert [f.severity for f in rows] == [Severity.LOW]


def test_the_row_names_the_server_without_carrying_the_spec(tmp_path: Path) -> None:
    inventories = _inventories(
        tmp_path,
        "repo/.mcp.json",
        {
            "loose": {"command": "npx", "args": ["-y", "secret-internal-package-name"]},
            "pinned": {"command": "npx", "args": ["-y", "other@1.2.3"]},
        },
    )
    rows = [f for inv in inventories for f in launch_findings(inv)]
    assert len(rows) == 1
    row = rows[0]
    assert row.evidence["server"] == "loose"
    assert row.evidence["observed_pin"] == "absent"
    assert row.evidence["accepted_pin"] == "exact"
    assert row.evidence["resolver"] == "npx"
    rendered = f"{row.title} {row.detail} {row.evidence}"
    assert "secret-internal-package-name" not in rendered
