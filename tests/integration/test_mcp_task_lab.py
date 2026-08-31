# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEP-2663 deferral, against a server whose extension plumbing is the SDK's own.

The unit suite for this class drives a fake transport, which answers with the
shape its author expected. This module runs the whole CLI path -
`run_mcp_scan` down to a written report - against lab/mcp/task_server.py, where
the extension is registered through MCPServer, the deferral is serialized by
the SDK's handler path, and the capability check is the SDK's
`require_client_extension`.

Three modes, three outcomes, and the point is that they are three. A scan that
reports the violation but cannot stay silent against the conformant server has
a detector that fires on everything; a scan that stays silent against both has
one that fires on nothing.
"""

from __future__ import annotations

import sys
from importlib import metadata
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed - pip install -e '.[lab]'")

_MCP_DIST_VERSION = metadata.version("mcp")
if int(_MCP_DIST_VERSION.split(".")[0]) < 2:
    pytest.skip(
        f"lab rig needs the mcp 2.x SDK, found {_MCP_DIST_VERSION} - pip install -e '.[lab]'",
        allow_module_level=True,
    )

REPO_ROOT = Path(__file__).resolve().parents[2]
RIG = REPO_ROOT / "lab" / "mcp" / "task_server.py"


def _scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, break_mode: str) -> list[dict[str, Any]]:
    """Run the product's own scan entry point against the rig in one mode.

    The rig is launched by path rather than as `-m lab.mcp.task_server`, and
    the mode arrives through the inherited environment. `run_mcp_scan` builds
    its StdioConfig with neither `env` nor `cwd`, so a rig that needed either
    could not be reached from the entry point the product actually ships - and
    a test that reached it another way would be exercising a path no operator
    has.
    """
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    monkeypatch.setenv("MAS_SENTRY_TASK_BREAK", break_mode)
    return run_mcp_scan(
        scheme="stdio",
        command=[sys.executable, str(RIG)],
        target_label=f"task-rig[{break_mode or 'conformant'}]",
        checks="all",
        out=tmp_path / f"task-{break_mode or 'clean'}.json",
        scope_confirmed=False,
    )


def _checks(rows: list[dict[str, Any]]) -> list[str]:
    return [r["check"] for r in rows]


def test_a_task_returned_to_a_client_that_never_asked_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = _scan(tmp_path, monkeypatch, "undeclared")
    deferred = [r for r in rows if r["check"] == "task_undeclared"]
    assert len(deferred) == 1
    assert deferred[0]["severity"] == "MEDIUM"
    detail = deferred[0]["detail"]
    assert "tools/call" in detail
    assert "io.modelcontextprotocol/tasks" in detail
    assert "did not run" in detail


def test_the_report_on_disk_carries_the_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The gap has to survive to the artifact, not just to the return value."""
    import json

    _scan(tmp_path, monkeypatch, "undeclared")
    written = json.loads((tmp_path / "task-undeclared.json").read_text())
    assert any(r["check"] == "task_undeclared" for r in written)


def test_a_conformant_server_that_runs_the_tool_produces_no_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = _scan(tmp_path, monkeypatch, "")
    assert "task_undeclared" not in _checks(rows)


def test_a_conformant_server_that_refuses_is_a_capability_gap_not_a_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """-32021 is the other legal answer, and it is already a different finding."""
    rows = _scan(tmp_path, monkeypatch, "refuse")
    assert "task_undeclared" not in _checks(rows)
    gaps = [r for r in rows if r["check"] == "capability_required"]
    assert len(gaps) == 1
    assert "io.modelcontextprotocol/tasks" in gaps[0]["detail"]
