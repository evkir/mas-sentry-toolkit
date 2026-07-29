# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end tests against the bundled vuln-mcp server (no docker required).

Spawns the local Python server via the stdio transport.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

LAB_SERVER = Path(__file__).parent.parent.parent / "lab" / "vuln-mcp" / "server.py"


@pytest.fixture(scope="module")
def vuln_mcp_client():
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    with open_stdio(StdioConfig(command=[sys.executable, str(LAB_SERVER)])) as t:
        yield McpClient(t)


@pytest.mark.skipif(not LAB_SERVER.exists(), reason="lab not present")
def test_vuln_mcp_initialize_returns_server_info(vuln_mcp_client):
    info = vuln_mcp_client.initialize()
    assert info.name == "vuln-mcp-lab"


@pytest.mark.skipif(not LAB_SERVER.exists(), reason="lab not present")
def test_vuln_mcp_tools_listed(vuln_mcp_client):
    vuln_mcp_client.initialize()
    names = {t.name for t in vuln_mcp_client.list_tools()}
    assert {"read_file", "fetch_url", "exec_cmd"}.issubset(names)


@pytest.mark.skipif(not LAB_SERVER.exists(), reason="lab not present")
def test_vuln_mcp_path_traversal_detected(vuln_mcp_client):
    from mas_sentry.protocols.mcp.audit.path_traversal import probe_path_traversal

    vuln_mcp_client.initialize()
    findings = probe_path_traversal(vuln_mcp_client)
    assert any(f.confirmed and "passwd" in f.payload for f in findings)


@pytest.mark.skipif(not LAB_SERVER.exists(), reason="lab not present")
def test_vuln_mcp_unlisted_surfaces_reach_the_report(tmp_path):
    """This server implements no prompts and no resources, and says so.

    Before the gap was recorded, the two refusals were flattened into empty
    lists and the scan claimed a coverage it never had. They are INFO, not a
    defect: -32601 means the surface does not exist.
    """
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    findings = run_mcp_scan(
        scheme="stdio",
        command=[sys.executable, str(LAB_SERVER)],
        target_label="vuln-mcp-lab",
        checks="fingerprint",
        out=tmp_path / "mcp.json",
        scope_confirmed=False,
    )
    gaps = {f["detail"].split(" ")[0]: f["severity"] for f in findings if f["check"] == "enumeration_gap"}
    assert gaps == {"prompts/list": "INFO", "resources/list": "INFO"}, findings
