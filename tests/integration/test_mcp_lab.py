# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP scans against the live lab server built on the reference SDK.

Every other MCP test in this repo feeds the client hand-written JSON-RPC
fixtures or drives the hand-rolled lab/vuln-mcp script, which implements only
the handful of methods MST already knew how to ask for. Both validate MST
against MST own idea of the wire. This module spawns the reference `mcp` SDK
server from lab/mcp/server.py and scans it over a real transport, so a
divergence between what MST emits and what a conforming server accepts shows up
as a test failure rather than as a silent empty scan in the field.

The HTTP cases are marked xfail(strict=True) on purpose. They encode the
behaviour the scanner is supposed to have and fail today, which is the finding:
over Streamable HTTP the reference server mints an `Mcp-Session-Id` on
initialize and rejects every later request without it, MST never carries it, and
the enumeration helpers degrade an error to an empty list - so a fully populated
server is reported as having no tools, no prompts and no resources at all.
strict=True means each one starts failing the suite the moment it is fixed but
not un-marked.

Skipped when the optional lab dependencies are absent (pip install -e .[lab]).
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed - pip install -e .[lab]")

REPO_ROOT = Path(__file__).resolve().parents[2]
STARTUP_TIMEOUT_S = 30.0
POLL_INTERVAL_S = 0.25

LAB_TOOLS = {"echo", "search_notes", "read_file", "fetch_url"}
LAB_PROMPTS = {"summarize"}
LAB_STATIC_RESOURCE = "file://lab/policy"
LAB_TEMPLATED_RESOURCE = "file://lab/notes/{name}"

_HTTP_SESSION_DEFECT = (
    "MST does not carry the Mcp-Session-Id minted by initialize, so every "
    "later request is rejected and enumeration degrades to empty lists"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _wait_for_port(port: int, deadline_s: float = STARTUP_TIMEOUT_S) -> bool:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(POLL_INTERVAL_S)
    return False


def _lab_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "PYTHONPATH": str(REPO_ROOT)}
    env.update(extra or {})
    return env


@pytest.fixture(scope="module")
def stdio_config():
    """STDIO rig config. No env override: STDIO is the rig default."""
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig

    return StdioConfig(command=[sys.executable, "-m", "lab.mcp.server"], cwd=str(REPO_ROOT))


@pytest.fixture(scope="module")
def http_url() -> Iterator[str]:
    """Spawn the rig on Streamable HTTP and yield its endpoint URL."""
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "lab.mcp.server"],
        cwd=str(REPO_ROOT),
        env=_lab_env(
            {
                "MCP_LAB_TRANSPORT": "streamable-http",
                "MCP_LAB_HOST": "127.0.0.1",
                "MCP_LAB_PORT": str(port),
            }
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        if not _wait_for_port(port):
            proc.terminate()
            out = proc.communicate(timeout=10)[0]
            pytest.fail(f"lab MCP server did not come up on {port}: {out!r}")
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _details(findings: list[dict], check: str) -> list[str]:
    return [f["detail"] for f in findings if f["check"] == check]


# --- STDIO: the transport that works today ---------------------------------


def test_stdio_enumerates_the_full_inventory(stdio_config) -> None:
    """Tools, prompts and resources all come back over STDIO."""
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import open_stdio

    with open_stdio(stdio_config) as transport:
        client = McpClient(transport)
        info = client.initialize()
        enumeration = client.enumerate_all()

    assert info.name == "vuln-mcp-ref"
    assert {t.name for t in enumeration.tools} == LAB_TOOLS
    assert {p.name for p in enumeration.prompts} == LAB_PROMPTS
    assert {r.uri for r in enumeration.resources} == {LAB_STATIC_RESOURCE}


def test_stdio_scan_flags_the_poisoned_tool(stdio_config, tmp_path: Path) -> None:
    """The poisoned description is caught on a real wire, not a fixture."""
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    findings = run_mcp_scan(
        scheme="stdio",
        command=stdio_config.command,
        target_label="lab-mcp-stdio",
        checks="poisoning",
        out=tmp_path / "mcp.json",
        scope_confirmed=False,
    )
    poisoning = _details(findings, "tool_poisoning")
    assert any(d.startswith("search_notes:") for d in poisoning), findings
    assert not any(d.startswith("echo:") for d in poisoning), "clean tool must not be flagged"


def test_stdio_scan_reads_the_poisoned_resource(stdio_config, tmp_path: Path) -> None:
    """Resource content is fetched and scanned for both injection and exfil."""
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    findings = run_mcp_scan(
        scheme="stdio",
        command=stdio_config.command,
        target_label="lab-mcp-stdio",
        checks="resources",
        out=tmp_path / "mcp.json",
        scope_confirmed=False,
    )
    resources = _details(findings, "resource_content")
    assert len(resources) == 1, findings
    detail = resources[0]
    assert detail.startswith(f"{LAB_STATIC_RESOURCE}:")
    assert "ignore-previous" in detail
    assert "markdown-image -> https://exfil.lab.invalid/pixel?d=" in detail


def test_stdio_scan_confirms_path_traversal(stdio_config, tmp_path: Path) -> None:
    """read_file has no guard, so the probe confirms rather than suspects."""
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    findings = run_mcp_scan(
        scheme="stdio",
        command=stdio_config.command,
        target_label="lab-mcp-stdio",
        checks="traversal",
        out=tmp_path / "mcp.json",
        scope_confirmed=False,
    )
    assert any(d.startswith("read_file:") for d in _details(findings, "path_traversal")), findings


@pytest.mark.xfail(
    strict=True,
    reason="resources/templates/list is never requested, so templated resources are invisible",
)
def test_templated_resources_are_enumerated(stdio_config) -> None:
    """A templated resource is part of the attack surface and must be listed."""
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import open_stdio

    with open_stdio(stdio_config) as transport:
        client = McpClient(transport)
        client.initialize()
        uris = {r.uri for r in client.list_resources()}

    assert LAB_TEMPLATED_RESOURCE in uris


# --- Streamable HTTP: pinned defect ----------------------------------------


@pytest.mark.xfail(strict=True, reason=_HTTP_SESSION_DEFECT)
def test_http_enumerates_the_full_inventory(http_url: str) -> None:
    """The same server, the same inventory, over the remote transport."""
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_http import HttpConfig, open_http

    with open_http(HttpConfig(url=http_url)) as transport:
        client = McpClient(transport)
        client.initialize()
        enumeration = client.enumerate_all()

    assert {t.name for t in enumeration.tools} == LAB_TOOLS
    assert {p.name for p in enumeration.prompts} == LAB_PROMPTS
    assert {r.uri for r in enumeration.resources} == {LAB_STATIC_RESOURCE}


@pytest.mark.xfail(strict=True, reason=_HTTP_SESSION_DEFECT)
def test_http_scan_flags_the_poisoned_tool(http_url: str, tmp_path: Path) -> None:
    """A populated remote server must not scan clean."""
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    findings = run_mcp_scan(
        scheme="http",
        command=http_url,
        target_label="lab-mcp-http",
        checks="poisoning",
        out=tmp_path / "mcp.json",
        scope_confirmed=False,
    )
    assert any(d.startswith("search_notes:") for d in _details(findings, "tool_poisoning")), findings


@pytest.mark.xfail(strict=True, reason=_HTTP_SESSION_DEFECT)
def test_http_fingerprint_counts_the_tools(http_url: str, tmp_path: Path) -> None:
    """The fingerprint line is what an operator reads first; zero is a lie."""
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    findings = run_mcp_scan(
        scheme="http",
        command=http_url,
        target_label="lab-mcp-http",
        checks="fingerprint",
        out=tmp_path / "mcp.json",
        scope_confirmed=False,
    )
    fingerprint = _details(findings, "fingerprint")
    assert fingerprint and f"({len(LAB_TOOLS)} tools)" in fingerprint[0], fingerprint
