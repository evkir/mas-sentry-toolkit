# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authorization announced at discovery and not applied at execution.

Source: CVE-2026-46519 (`mcp-server-kubernetes` 0.2.4-3.5.1, fixed 3.6.0,
CWE-863, CVSS 8.8; OSV / GHSA-cr22-wjx7-2w6m), read off the published packages:
3.5.1 and 3.6.0 ship identical file trees, and the whole fix is the guard
`if (!isToolAllowed(name))` added to the `CallToolRequestSchema` handler that
the `ListToolsRequestSchema` handler already had. A client holding the name of
a filtered-out tool reached it regardless.

No competitor sees this. mcp-scan reads client configs, mcphound matches CVEs
by name, and neither asks the target a question. It is also observable without
executing anything, which is what makes it shippable under R-7.6 at all.

Two things had to be settled before a line of the probe could be written, and
both were settled against live servers rather than reasoned about.

**Where the name comes from.** It is not in `tools/list` by definition. The
plan ranked three sources and rejected only a dictionary of common names; a
knowledge table has to be rejected too, and for a reason the plan did not have.
A table supplies a name and no input schema, and without the schema the only
call a probe can make is one with empty arguments - which, measured on both
reference SDKs, *executes the tool body* whenever nothing in its schema is
required. That makes a table exactly as unsafe as the dictionary it was
preferred over. What remains is MST's own baseline: a name and a schema the
scanner itself observed being advertised.

**How the answer is read.** The plan's criterion was to tell `-32601` from
`-32602`. Measured, neither reference implementation uses `-32601` at all, and
the TypeScript SDK answers `-32602` to both an unknown name and bad arguments,
so the distinction does not exist on the wire. What does exist is a difference
between the answer to a name the server does not know and the answer to one it
does, and it is read differentially, against two references taken from the same
target in the same scan:

    A  a name that cannot exist, so the answer means "not recognised here"
    B  an announced tool called invalidly, so the answer means "recognised,
       arguments refused"
    T  the withdrawn name, called invalidly by the schema the baseline holds

Normalising tool names out of the three answers and measuring the shared prefix
of each against B:

    implementation              A vs B     T vs B (desync)   T when fixed
    mcp 2.3.0 (Python)           0 ch        68 ch           JSON-RPC error
    @modelcontextprotocol/sdk    18 ch      126 ch           JSON-RPC error
    1.32.1 (TypeScript)

The two populations do not overlap, and the error codes behind the fixed column
differ between the implementations (-32603 and -32600), which is why nothing
here is allowed to read a code. The rig covers both halves of R-2.4: the
filtered shape must produce the finding, the fixed shape must produce none.

The marker is the guard that keeps this honest. The rig's hidden tool writes a
file when its body runs, and every case below asserts the file is absent. The
claim of this operation is reachability established without execution, and an
unasserted claim of that kind is how the day-5 canary turned into a false
positive.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app

pytest.importorskip("mcp.server.mcpserver", reason="lab rig needs the mcp 2.x SDK")

runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parents[2]
HIDDEN = "sweep_cluster"


@pytest.fixture
def marker(tmp_path: Path) -> Path:
    """Where the hidden tool's body would announce itself. Fresh per test."""
    return tmp_path / "body-ran"


def _scan(mode: str, marker: Path, out: Path, baseline: Path, checks: str = "all") -> list[dict[str, object]]:
    """One `mcp scan` against the rig in one of its three modes."""
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
            "--tool-baseline",
            str(baseline),
            "--cwd",
            str(REPO_ROOT),
            "--env",
            f"MAS_SENTRY_DESYNC_MODE={mode}",
            "--env",
            f"MAS_SENTRY_DESYNC_MARKER={marker}",
        ],
    )
    assert result.exit_code == 0, result.output
    rows: list[dict[str, object]] = json.loads(out.read_text(encoding="utf-8"))
    return rows


def _approved_then(mode: str, marker: Path, tmp_path: Path) -> list[dict[str, object]]:
    """Capture a baseline while the tool is advertised, then scan the filtered target.

    This is the sequence the CVE describes: an operator approves an inventory,
    the server is reconfigured to hide part of it, and the hidden part stays
    callable.
    """
    baseline = tmp_path / "baseline.json"
    _scan("off", marker, tmp_path / "approved.json", baseline, checks="drift")
    return _scan(mode, marker, tmp_path / "scan.json", baseline)


def test_the_rig_hides_a_tool_it_still_executes(marker: Path, tmp_path: Path) -> None:
    """The reality check for the defect half. Not xfailed: it pins the rig.

    Both halves are asserted, because either one alone would let every case
    below pass for the wrong reason: the tool is absent from the listing, and a
    direct call with valid arguments runs its body.
    """
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    env = dict(
        os.environ,
        MAS_SENTRY_DESYNC_MODE="list-only",
        MAS_SENTRY_DESYNC_MARKER=str(marker),
    )
    config = StdioConfig(command=[sys.executable, "-m", "lab.mcp.desync_server"], cwd=str(REPO_ROOT), env=env)
    with open_stdio(config) as transport:
        client = McpClient(transport)
        client.connect()
        assert HIDDEN not in [t.name for t in client.list_tools()], "the rig must hide it from discovery"
        answer = client.send("tools/call", {"name": HIDDEN, "arguments": {"namespace": "kube-system"}})

    assert answer.error is None, "and must still execute it"
    assert marker.exists(), "the body ran, which is what makes the desync real"


def test_the_fixed_mode_refuses_the_call_outright(marker: Path, tmp_path: Path) -> None:
    """The reality check for the fixed half. Not xfailed: it pins the rig."""
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    env = dict(os.environ, MAS_SENTRY_DESYNC_MODE="both", MAS_SENTRY_DESYNC_MARKER=str(marker))
    config = StdioConfig(command=[sys.executable, "-m", "lab.mcp.desync_server"], cwd=str(REPO_ROOT), env=env)
    with open_stdio(config) as transport:
        client = McpClient(transport)
        client.connect()
        answer = client.send("tools/call", {"name": HIDDEN, "arguments": {"namespace": "kube-system"}})

    assert answer.error is not None, "the fix refuses the call before the handler"
    assert not marker.exists(), "so the body never runs"


@pytest.mark.xfail(strict=True, reason="nothing probes whether a withdrawn tool is still callable")
def test_a_withdrawn_tool_that_is_still_callable_is_reported(marker: Path, tmp_path: Path) -> None:
    """The finding, and the bound on how it was obtained, in one case.

    Both assertions belong together: a row produced by running the tool would
    satisfy the first and fail the second, and that trade is the one this
    operation exists to refuse.
    """
    rows = _approved_then("list-only", marker, tmp_path)
    hits = [row for row in rows if row["check"] == "authz_desync"]
    assert hits, "the tool is absent from the listing and answers a call, which is the weakness"
    assert HIDDEN in str(hits[0]["detail"]), "the row names the tool it is about"
    assert not marker.exists(), "and the probe established that without executing the tool (R-7.6)"


@pytest.mark.xfail(strict=True, reason="nothing probes whether a withdrawn tool is still callable")
def test_a_filter_on_both_levels_produces_no_finding(marker: Path, tmp_path: Path) -> None:
    """The other half of R-2.4: a server that did it right must come out clean.

    A patched target that still produced a CRITICAL row would make the whole
    operation worthless, which is the shape the day-5 canary had.
    """
    rows = _approved_then("both", marker, tmp_path)
    assert [row for row in rows if row["check"] == "authz_desync"] == [], "the fixed shape is silent"
    unresolved = [row for row in rows if row["check"] == "authz_desync_unverified"]
    assert unresolved, "silence about the weakness is not silence about the probe (R-7.5)"
    assert not marker.exists()


@pytest.mark.xfail(strict=True, reason="there is no authz row, so nothing carries the two layers it spans")
def test_the_row_carries_both_layers_it_spans(marker: Path, tmp_path: Path) -> None:
    """R-7.2 for a finding whose whole content is a disagreement between levels."""
    rows = _approved_then("list-only", marker, tmp_path)
    row = next(row for row in rows if row["check"] == "authz_desync")

    assert row["announced"] == "absent from tools/list", "what discovery said"
    assert row["observed"], "what the call answered"
    assert row["reference_unknown_tool"], "the answer the same target gives a name it does not know"
    assert row["name_source"] == "baseline", "and where a name MST never saw advertised came from"
