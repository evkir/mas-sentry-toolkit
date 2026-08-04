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
