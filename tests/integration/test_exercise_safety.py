# SPDX-License-Identifier: AGPL-3.0-or-later
"""A default scan must not run an operation on the target.

Separate from the desync lab that shares the rig with it, because the claim is
a different one. There, the marker guards a probe that establishes reachability
without execution. Here it guards the scan as a whole: the mutation audit calls
tools on purpose, to open the window a rug pull fires in, and what it may call
is bounded by a name test with no knowledge of what the tool does.

The rig in `off` mode is the honest shape for this. Nothing is filtered, so
`sweep_cluster` is advertised like any other tool, and a scan that calls it is
not being tricked - it is calling a tool a server offered, under a name whose
first word is a destructive verb, having been given no reason to believe the
call is safe. Its body writes the marker, which is the only reason this is
observable at all rather than being a claim about code.

Narrowed to `mutation` after measuring all nine checks against this rig: that
one creates the marker and the other eight do not, so the row this pins belongs
to one module rather than to the scan in general. `all` is asserted as well,
because that is the command an operator actually types, and the default.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app

pytest.importorskip("mcp.server.mcpserver", reason="lab rig needs the mcp 2.x SDK")

runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parents[2]
HIDDEN = "sweep_cluster"


def _scan_unfiltered(checks: str, marker: Path, out: Path) -> list[dict[str, object]]:
    """One scan of the rig with nothing filtered out of its listing."""
    result = runner.invoke(
        app,
        [
            "mcp",
            "scan",
            "--target",
            f"stdio://{sys.executable} -m lab.mcp.desync_server",
            "--checks",
            checks,
            "-o",
            str(out),
            "--cwd",
            str(REPO_ROOT),
            "--env",
            "MAS_SENTRY_DESYNC_MODE=off",
            "--env",
            f"MAS_SENTRY_DESYNC_MARKER={marker}",
        ],
    )
    assert result.exit_code == 0, result.output
    rows: list[dict[str, object]] = json.loads(out.read_text(encoding="utf-8"))
    return rows


def _assert_the_rig_was_reached(rows: list[dict[str, object]]) -> None:
    """Without this the marker's absence would also be what a dead rig looks like."""
    fingerprints = [r for r in rows if r["check"] == "fingerprint"]
    assert len(fingerprints) == 1
    assert "2 tools" in str(fingerprints[0]["detail"])


@pytest.mark.xfail(strict=True, reason="selection is a blocklist, and 'sweep' was never enumerated")
@pytest.mark.parametrize("checks", ["mutation", "all"])
def test_a_scan_does_not_execute_a_tool_it_only_found_a_name_for(checks: str, tmp_path: Path) -> None:
    """Both halves, because either alone passes for the wrong reason.

    The rig has to have been reached and enumerated - otherwise an absent
    marker says the scan failed early, which is the same file on disk as a
    scan that behaved. And the marker has to be absent, which is the claim.
    """
    marker = tmp_path / "body-ran"
    rows = _scan_unfiltered(checks, marker, tmp_path / "scan.json")
    _assert_the_rig_was_reached(rows)
    assert not marker.exists(), f"{HIDDEN} ran: {checks} executed a tool body on the target"
