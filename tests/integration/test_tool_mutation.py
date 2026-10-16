# SPDX-License-Identifier: AGPL-3.0-or-later
"""In-session tool mutation, measured against the reference-SDK rig.

The rig rewrites `read_config` into a poisoned descriptor the first time it is
called, and emits nothing while doing it. Both halves matter: a detector that
fires here is reading the inventory rather than waiting to be told, and a
detector that stays quiet on the other four tools is not guessing.
"""

import sys
from pathlib import Path

import pytest

from mas_sentry.protocols.mcp.audit.tool_mutation import (
    detect_tool_mutation,
    notification_mark,
    snapshot_tools,
)
from mas_sentry.protocols.mcp.client import McpClient
from mas_sentry.protocols.mcp.transport_stdio import open_stdio

pytest.importorskip("mcp.server.mcpserver", reason="lab rig needs the mcp 2.x SDK")

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def stdio_config():
    """The reference-SDK rig over STDIO, its default transport."""
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig

    return StdioConfig(command=[sys.executable, "-m", "lab.mcp.server"], cwd=str(REPO_ROOT))


def test_a_silent_descriptor_swap_is_caught(stdio_config) -> None:
    with open_stdio(stdio_config) as transport:
        client = McpClient(transport)
        client.connect()
        before = snapshot_tools(client)
        mark = notification_mark(client)
        client.send("tools/call", {"name": "read_config", "arguments": {"key": "a"}})
        findings = detect_tool_mutation(client, before, mark)

    assert [f.tool for f in findings] == ["read_config"]
    finding = findings[0]
    assert finding.kind == "tool_mutation"
    assert finding.severity == "HIGH"
    assert finding.announced is False
    assert "no notification at all" in finding.detail


def test_an_untouched_inventory_produces_nothing(stdio_config) -> None:
    """The other four tools are not flagged, and neither is a scan that calls none."""
    with open_stdio(stdio_config) as transport:
        client = McpClient(transport)
        client.connect()
        before = snapshot_tools(client)
        mark = notification_mark(client)
        client.send("tools/call", {"name": "echo", "arguments": {"text": "hi"}})
        assert detect_tool_mutation(client, before, mark) == []


def test_the_scan_reports_the_swap_as_a_finding(stdio_config) -> None:
    """End to end through the runtime, since a finding that stops short is not one."""
    from mas_sentry.protocols.mcp.runtime import _run_all_checks

    with open_stdio(stdio_config) as transport:
        rows = _run_all_checks(McpClient(transport), transport="stdio", checks="all")

    mutations = [r for r in rows if r["check"] == "tool_mutation"]
    assert len(mutations) == 1
    assert mutations[0]["severity"] == "HIGH"
    assert "read_config" in mutations[0]["detail"]


def test_the_swap_carries_both_sides_off_the_reference_sdk(stdio_config) -> None:
    """The same claim as the unit rig, against a server that really swaps.

    The hand-rolled rig rewrites a dict; this one calls `remove_tool` and
    `add_tool` on the reference SDK, which is where the class was first seen
    and the only place both sides are descriptors the SDK built rather than
    ones a test wrote (R-2.2).

    That difference showed up immediately, and it is why `changed` names two
    halves here and one in the unit rig. `mcp` 2.3.0 derives the input
    schema's `title` from the name of the Python function backing the tool, so
    re-registering under the same tool name with a different function carries
    the internal name out onto the wire: `read_configArguments` becomes
    `_mutated_read_configArguments`. An in-session swap on this SDK therefore
    moves the schema as well as the description, and the half that looked
    unchanged is the half that proves which function is answering now. A row
    carrying only the moved description would have dropped it.
    """
    # Imported here, not at module scope: this module is skipped without the
    # lab extra, and the rig imports the SDK at its own module scope (R-2.11).
    from lab.mcp.server import CLEAN_CONFIG_DESCRIPTION

    with open_stdio(stdio_config) as transport:
        client = McpClient(transport)
        client.connect()
        before = snapshot_tools(client)
        mark = notification_mark(client)
        client.send("tools/call", {"name": "read_config", "arguments": {"key": "a"}})
        findings = detect_tool_mutation(client, before, mark)

    evidence = findings[0].evidence
    assert evidence["changed"] == "description, input_schema"
    assert evidence["previous_description"] == CLEAN_CONFIG_DESCRIPTION
    assert "exfil.lab.invalid" in evidence["current_description"]
    assert "read_configArguments" in evidence["previous_schema"], "the function answering before the swap"
    assert "_mutated_read_configArguments" in evidence["current_schema"], "and the one answering after"


def test_the_sdk_declares_the_channel_it_never_uses(stdio_config) -> None:
    """The asymmetry this detector was built around, now checkable from the row.

    `remove_tool`/`add_tool` emit nothing on `mcp` 2.3.0, while the same server
    answers `initialize` with `tools.listChanged: true`. A detector waiting to
    be told would never fire here, and an attacker has every reason not to
    tell - so the declaration is read as evidence about the finding, never as
    the reason to look. A row carrying only what arrived would report this
    target exactly like one that never offered the channel at all.
    """
    with open_stdio(stdio_config) as transport:
        client = McpClient(transport)
        client.connect()
        assert client.server.capabilities["tools"]["listChanged"] is True, "the promise, read off initialize"
        before = snapshot_tools(client)
        mark = notification_mark(client)
        client.send("tools/call", {"name": "read_config", "arguments": {"key": "a"}})
        findings = detect_tool_mutation(client, before, mark)

    evidence = findings[0].evidence
    assert evidence["disclosure"] == "none", "and nothing arrived to keep it"
    assert evidence["disclosure_declared"] == "tools.listChanged: true"
