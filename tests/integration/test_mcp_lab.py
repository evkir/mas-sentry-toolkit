# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP scans against the live lab server built on the reference SDK.

Every other MCP test in this repo feeds the client hand-written JSON-RPC
fixtures or drives the hand-rolled lab/vuln-mcp script, which implements only
the handful of methods MST already knew how to ask for. Both validate MST
against MST own idea of the wire. This module spawns the reference `mcp` SDK
server from lab/mcp/server.py and scans it over a real transport, so a
divergence between what MST emits and what a conforming server accepts shows up
as a test failure rather than as a silent empty scan in the field.

Every case here was pinned as xfail(strict=True) when this module landed. The
reference server mints an `Mcp-Session-Id` on initialize and rejects every later
request without it, MST never carried it, and the enumeration helpers degrade an
error to an empty list, so a fully populated server was reported as having no
tools, no prompts and no resources at all. The transport now carries the session
and the negotiated revision, and resources/templates/list is now requested, so
they assert normally.

Skipped when the optional lab dependencies are absent (pip install -e .[lab]).
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from importlib import metadata
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed - pip install -e '.[lab]'")

# Presence is not enough. The rig imports mcp.server.mcpserver, which exists only
# in the 2.x line, so an environment holding an mcp 1.x - a sibling project
# pinning mcp<2 into the same interpreter will do it - passes the import check
# and then fails every case here with a protocol-shaped error that has nothing
# to do with the protocol. Skipping on the version says what is actually wrong.
_MCP_DIST_VERSION = metadata.version("mcp")
if int(_MCP_DIST_VERSION.split(".")[0]) < 2:
    pytest.skip(
        f"lab rig needs the mcp 2.x SDK, found {_MCP_DIST_VERSION} - pip install -e '.[lab]'",
        allow_module_level=True,
    )

REPO_ROOT = Path(__file__).resolve().parents[2]
STARTUP_TIMEOUT_S = 30.0
POLL_INTERVAL_S = 0.25

LAB_TOOLS = {"echo", "search_notes", "read_file", "fetch_url", "read_config"}
LAB_PROMPTS = {"summarize"}
LAB_STATIC_RESOURCE = "file://lab/policy"
LAB_TEMPLATED_RESOURCE = "file://lab/notes/{name}"


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
def paged_stdio_config():
    """The same rig, serving tools/list two at a time."""
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig

    return StdioConfig(
        command=[sys.executable, "-m", "lab.mcp.server"],
        env=_lab_env({"MCP_LAB_PAGE_SIZE": "2"}),
        cwd=str(REPO_ROOT),
    )


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


def test_templated_resources_are_enumerated(stdio_config) -> None:
    """A templated resource is part of the attack surface and must be listed.

    It lives behind its own method, so a client that only asks for concrete
    resources sees a smaller server than the one in front of it.
    """
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import open_stdio

    with open_stdio(stdio_config) as transport:
        client = McpClient(transport)
        client.initialize()
        enumeration = client.enumerate_all()

    assert {t.uri_template for t in enumeration.resource_templates} == {LAB_TEMPLATED_RESOURCE}
    assert {r.uri for r in enumeration.resources} == {LAB_STATIC_RESOURCE}


def test_a_poisoned_template_description_is_flagged(stdio_config, tmp_path: Path) -> None:
    """The description is what an agent reads before expanding the template."""
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    findings = run_mcp_scan(
        scheme="stdio",
        command=stdio_config.command,
        target_label="lab-mcp-stdio",
        checks="resources",
        out=tmp_path / "mcp.json",
        scope_confirmed=False,
    )
    templates = _details(findings, "resource_template")
    assert len(templates) == 1, findings
    assert templates[0].startswith(f"{LAB_TEMPLATED_RESOURCE}:")
    assert "ignore-previous" in templates[0]


# --- Streamable HTTP: the transport the session fix unblocked ---------------


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


def test_http_transport_adopts_the_session_and_revision(http_url: str) -> None:
    """The session and the negotiated revision are read off the wire, not guessed."""
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_http import HttpConfig, open_http

    with open_http(HttpConfig(url=http_url)) as transport:
        info = McpClient(transport).initialize()
        assert transport.session_id, "server minted a session that was not adopted"
        assert transport.protocol_version == info.protocol_version


def test_http_negotiates_the_stateless_route(http_url: str) -> None:
    """connect() reaches the modern rig without a handshake and reads its identity.

    The identity check matters on its own: discover returns serverInfo nested in
    result._meta, where the handshake returned it at the top level, so a client
    reading the old place gets a nameless server and every known-implementation
    CVE match silently stops working.
    """
    from mas_sentry.protocols.mcp.client import MODERN_PROTOCOL_VERSION, McpClient
    from mas_sentry.protocols.mcp.transport_http import HttpConfig, open_http

    with open_http(HttpConfig(url=http_url)) as transport:
        client = McpClient(transport)
        info = client.connect()
        assert client.is_modern
        assert client.protocol_version == MODERN_PROTOCOL_VERSION
        assert info.name, "server identity was not read from the discover result"


def test_the_reference_server_rejects_every_header_body_desync(http_url: str) -> None:
    """The negative control for the desync audit.

    A one-sided detector is one that may never fire. The permissive half is
    covered by unit tests; this asserts that a conforming server refuses all
    four probes, so a HIGH from this check means the target really differs from
    the reference implementation rather than from our idea of it.
    """
    from mas_sentry.protocols.mcp.audit.header_desync import probe_header_desync
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_http import HttpConfig, open_http

    with open_http(HttpConfig(url=http_url)) as transport:
        client = McpClient(transport)
        client.connect()
        tools = client.list_tools()
        resources = client.list_resources()
        findings = probe_header_desync(
            client,
            tool_name=tools[0].name,
            resource_uri=resources[0].uri if resources else "",
        )
    assert len(findings) == 4
    assert {f.status for f in findings} == {"rejected"}


def test_a_paginated_inventory_is_walked_to_the_end(paged_stdio_config) -> None:
    """An inventory served two at a time is still the whole inventory.

    The reference server pages through the SDK result model, so the cursor
    shape is the real one rather than our own idea of it. A client reading only
    the first page would report half this inventory and audit half the surface.
    """
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import open_stdio

    with open_stdio(paged_stdio_config) as transport:
        client = McpClient(transport)
        client.initialize()
        tools = client.list_tools()

    assert {t.name for t in tools} == LAB_TOOLS
    assert client.enumeration_issues == []
