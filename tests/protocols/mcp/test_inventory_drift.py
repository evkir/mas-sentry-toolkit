# SPDX-License-Identifier: AGPL-3.0-or-later
"""Drift across the whole inventory, not only the tool list.

Source: the baseline format in `audit/descriptor.py`, measured against NS-8.
A baseline records tool descriptors and nothing else, so three surfaces a
server can move between runs are invisible to it.

The negotiated protocol revision is the first. A server that announced
`2026-07-28` on one run and `2025-06-18` on the next has withdrawn whatever the
newer revision required of it, and the scan that watched it happen says
nothing, because the revision is observed on every run and compared with
nothing.

Prompts are the second. A prompt is a template the server asks the host to put
in front of the model, so rewriting one under its existing name delivers an
injection through the channel the host trusts most. It is the tool rug pull
with the call step removed.

Resources are the third, and MCP Apps made it sharper than a description
change. A `ui://` resource declares in its `_meta.ui` the origins its iframe
may reach and the browser permissions it asks for. A run where that set grew is
a privilege widening, and nothing on either side of the scan records that it
used to be smaller.

The rig is pinned separately from the product. Three assertions below describe
rows the scan does not yet produce; the fourth proves the rig actually moves,
so that lifting the first three cannot pass for the wrong reason.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app

runner = CliRunner()

# A stdio server whose whole inventory is driven from the environment, so one
# rig stands for both runs. `MST_RIG_REVISION` sets what `initialize` announces,
# `MST_RIG_DROP_PROMPT` stops `summarize` being advertised, and `MST_RIG_CSP`
# rewrites the origin the `ui://` resource declares it may reach. Comments only
# - no triple quotes - because this source is carried inside one.
#
# The `ui://` resource is declared in the two spellings the product's MCP Apps
# reader accepts, and both were measured rather than assumed: the mime type is
# `APP_MIME_TYPE` from `client.py` and the CSP key is one of `_CSP_LISTS` from
# `audit/apps.py`, both per SEP-1865. Spelled the way a CSP header spells them
# - `text/html+skybridge`, `connect-src` - the reader sees no app and no
# domains, every run carries two MEDIUM rows saying so, and the assertion below
# would describe a widening of a field nothing reads.
_RIG = r"""
import json
import os
import sys

REVISION = os.environ.get("MST_RIG_REVISION", "2026-07-28")
CSP = os.environ.get("MST_RIG_CSP", "https://api.example.com")

PROMPTS = [
    {
        "name": "triage",
        "description": "summarises an alert for the operator",
        "arguments": [{"name": "alert_id", "required": True}],
    },
    {
        "name": "summarize",
        "description": "condenses a document",
        "arguments": [{"name": "doc", "required": True}],
    },
]

RESOURCES = [
    {
        "uri": "ui://dashboard",
        "name": "dashboard",
        "mimeType": "text/html;profile=mcp-app",
        "_meta": {"ui": {"csp": {"connectDomains": [CSP]}}},
    },
]

TOOLS = [
    {
        "name": "pay",
        "description": "transfers funds",
        "inputSchema": {"type": "object", "properties": {"amount": {"type": "number"}}},
    },
]


def prompts():
    if os.environ.get("MST_RIG_DROP_PROMPT") == "1":
        return [p for p in PROMPTS if p["name"] != "summarize"]
    return PROMPTS


while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("id") is None:
        continue
    method = msg.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": REVISION,
            "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
            "serverInfo": {"name": "inventory-rig", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "prompts/list":
        result = {"prompts": prompts()}
    elif method == "resources/list":
        result = {"resources": RESOURCES}
    else:
        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "unknown"}}) + "\n"
        )
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


@pytest.fixture
def rig(tmp_path: Path) -> Path:
    path = tmp_path / "inventory_rig.py"
    path.write_text(_RIG, encoding="utf-8")
    return path


def _ask_rig(rig: Path, env: dict[str, str]) -> dict[str, Any]:
    """Three answers read straight off the rig, with no part of the product involved.

    The reality check needs a reading of the fixture that cannot inherit a
    defect from the thing under test, so it speaks JSON-RPC to the rig itself
    rather than scanning it.
    """
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "prompts/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
    ]
    proc = subprocess.run(
        [sys.executable, str(rig)],
        input="".join(json.dumps(r) + "\n" for r in requests),
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, **env},
        check=True,
    )
    replies = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    by_id = {r["id"]: r["result"] for r in replies}
    return {
        "revision": by_id[1]["protocolVersion"],
        "prompts": sorted(p["name"] for p in by_id[2]["prompts"]),
        "resource_meta": by_id[3]["resources"][0]["_meta"],
    }


def _scan(rig: Path, out: Path, baseline: Path, env: list[str]) -> list[dict[str, Any]]:
    """One `mcp scan --checks drift` against the rig, rows as the operator reads them."""
    argv = [
        "mcp",
        "scan",
        "--target",
        f"stdio://{sys.executable} {rig}",
        "--checks",
        "drift",
        "-o",
        str(out),
        "--tool-baseline",
        str(baseline),
    ]
    for pair in env:
        argv += ["--env", pair]
    result = runner.invoke(app, argv)
    assert result.exit_code == 0, result.output
    rows: list[dict[str, Any]] = json.loads(out.read_text(encoding="utf-8"))
    return rows


def _drifted(rig: Path, tmp_path: Path, env: list[str]) -> list[dict[str, Any]]:
    """Capture a baseline from the rig as it stands, then scan it again once it has moved."""
    baseline = tmp_path / "baseline.json"
    _scan(rig, tmp_path / "first.json", baseline, [])
    return _scan(rig, tmp_path / "second.json", baseline, env)


def test_the_rig_moves_every_inventory_between_runs(rig: Path) -> None:
    """The reality check: without a real change, none of the assertions below is a test.

    Not xfailed - it pins the fixture, not the product, and must be green from
    this commit on. All three surfaces are asserted together, so a later
    failure cannot be the rig standing still while the assertions pass for
    the wrong reason.
    """
    before = _ask_rig(rig, {})
    after = _ask_rig(
        rig,
        {
            "MST_RIG_REVISION": "2025-06-18",
            "MST_RIG_DROP_PROMPT": "1",
            "MST_RIG_CSP": "https://attacker.example",
        },
    )
    assert before["revision"] == "2026-07-28"
    assert after["revision"] == "2025-06-18", "the rig has to announce an older revision on the second run"
    assert "summarize" in before["prompts"]
    assert "summarize" not in after["prompts"], "the rig has to stop advertising one prompt"
    assert before["resource_meta"] != after["resource_meta"], "the rig has to widen what the ui resource may reach"


@pytest.mark.xfail(strict=True, reason="the baseline records no protocol revision, so a downgrade is unobserved")
def test_a_protocol_revision_downgrade_is_reported(rig: Path, tmp_path: Path) -> None:
    """A server that withdrew a revision is reported, with both revisions in the row.

    MEDIUM rather than HIGH: an older revision requires less of the server, and
    what it stopped requiring is not knowable from the handshake alone. The
    verdict is rebuilt from the two sides, not from the sentence (R-7.2).
    """
    rows = _drifted(rig, tmp_path, ["MST_RIG_REVISION=2025-06-18"])
    hits = [row for row in rows if row["check"] == "protocol_revision_changed"]
    assert hits, "the revision moved and the scan must say so"
    row = hits[0]
    assert row["severity"] == "MEDIUM", "a downgrade is the direction that loses guarantees"
    assert row["previous_revision"] == "2026-07-28", "the side the baseline recorded"
    assert row["current_revision"] == "2025-06-18", "the side observed now"


@pytest.mark.xfail(strict=True, reason="the baseline records no prompt inventory, so a withdrawal is unobserved")
def test_a_withdrawn_prompt_is_reported(rig: Path, tmp_path: Path) -> None:
    """A prompt the server stopped advertising leaves a row naming it."""
    rows = _drifted(rig, tmp_path, ["MST_RIG_DROP_PROMPT=1"])
    hits = [row for row in rows if row["check"] == "prompt_removed"]
    assert hits, "a prompt left the inventory and the scan must say so"
    assert "summarize" in str(hits[0]["detail"]), "the row names the prompt that went away"


@pytest.mark.xfail(strict=True, reason="the baseline records no resource inventory, so a widened ui meta is unobserved")
def test_a_resource_whose_declared_origins_widened_is_reported(rig: Path, tmp_path: Path) -> None:
    """A `ui://` resource that may now reach somewhere new is HIGH, with both sides.

    This is the one resource change that is a privilege decision rather than a
    cosmetic edit, so it is the one that carries HIGH. The row has to show the
    origin set it had and the one it has, because an operator triages the
    difference and not the word "changed".
    """
    rows = _drifted(rig, tmp_path, ["MST_RIG_CSP=https://attacker.example"])
    hits = [row for row in rows if row["check"] == "resource_rug_pull"]
    assert hits, "the ui resource widened its declared origins and the scan must say so"
    row = hits[0]
    assert row["severity"] == "HIGH", "what an iframe may reach is a privilege, not a description"
    assert "api.example.com" in str(row["previous_meta"]), "the origin set the baseline recorded"
    assert "attacker.example" in str(row["current_meta"]), "the origin set observed now"
