# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEP-2549 and the instructions string, against the reference SDK on a real wire.

The unit suites for both audits feed the client hand-written results, which
proves the rules and nothing about the wire: a field named `ttlMs` in a fixture
and a field named `ttlMs` by the SDK are the same string only until one of them
is not. These cases drive the reference server, so the names, the defaults and
the capability declaration are the ones a real client meets.

Two of them exist to hold a boundary rather than to catch a defect. A
conformant server must produce no caching row at all, and the reference server
declares a change channel it then does not use - which is exactly the
declaration cache_stale_window trusts when it stays quiet.

Skipped when the optional lab dependencies are absent (pip install -e .[lab]).
"""

from __future__ import annotations

import sys
from importlib import metadata
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed - pip install -e '.[lab]'")

_MCP_DIST_VERSION = metadata.version("mcp")
if int(_MCP_DIST_VERSION.split(".")[0]) < 2:
    pytest.skip(
        f"lab rig needs the mcp 2.x SDK, found {_MCP_DIST_VERSION} - pip install -e '.[lab]'",
        allow_module_level=True,
    )

REPO_ROOT = Path(__file__).resolve().parents[2]


def _lab_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "PYTHONPATH": str(REPO_ROOT)}
    env.update(extra or {})
    return env


def test_the_freshness_fields_arrive_from_the_sdk_itself() -> None:
    """Both routes of capture, against the names the reference server puts on the wire."""
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    config = StdioConfig(command=[sys.executable, "-m", "lab.mcp.server"], env=_lab_env(), cwd=str(REPO_ROOT))
    with open_stdio(config) as transport:
        client = McpClient(transport)
        client.connect()
        client.list_tools()

    recorded = {hint.method for hint in client.cache_hints}
    assert "server/discover" in recorded, "the discover result carries the fields and was not recorded"
    assert "tools/list" in recorded
    assert all(hint.ttl_present and hint.scope_present for hint in client.cache_hints)
    # The SDK defaults: immediately stale, and never shared.
    assert {(hint.ttl_ms, hint.cache_scope) for hint in client.cache_hints} == {(0, "private")}


def test_a_conformant_server_produces_no_caching_row() -> None:
    """A check no reference default can clear is noise; this is the test that says so."""
    from mas_sentry.protocols.mcp.audit.caching import audit_caching
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    config = StdioConfig(command=[sys.executable, "-m", "lab.mcp.server"], env=_lab_env(), cwd=str(REPO_ROOT))
    with open_stdio(config) as transport:
        client = McpClient(transport)
        client.connect()
        client.enumerate_all()
        findings = audit_caching(client)

    assert findings == [], f"the reference SDK triggered {[f.check for f in findings]}"


def test_pages_that_disagree_are_caught_on_a_real_wire() -> None:
    """The one caching defect a reference-SDK rig can produce without bypassing its model."""
    from mas_sentry.protocols.mcp.audit.caching import PUBLIC_WINDOW_CHECK, SCOPE_SPLIT_CHECK, audit_caching
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    config = StdioConfig(
        command=[sys.executable, "-m", "lab.mcp.server"],
        env=_lab_env({"MCP_LAB_CACHE_BREAK": "1"}),
        cwd=str(REPO_ROOT),
    )
    with open_stdio(config) as transport:
        client = McpClient(transport)
        client.connect()
        client.list_tools()
        findings = audit_caching(client)

    checks = [f.check for f in findings]
    assert SCOPE_SPLIT_CHECK in checks, findings
    assert PUBLIC_WINDOW_CHECK in checks, findings
    pages = [hint for hint in client.cache_hints if hint.method == "tools/list"]
    assert len(pages) > 1, "the rig served one page, so there was nothing to disagree"
    assert {hint.cache_scope for hint in pages} == {"public", "private"}


def test_hostile_instructions_are_read_off_the_handshake() -> None:
    """The prose a host would place in model context, audited from a live server."""
    from mas_sentry.protocols.mcp.audit.instructions import CONCEALMENT_CHECK, audit_instructions
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    config = StdioConfig(
        command=[sys.executable, "-m", "lab.mcp.server"],
        env=_lab_env({"MCP_LAB_INSTRUCTIONS": "hostile"}),
        cwd=str(REPO_ROOT),
    )
    with open_stdio(config) as transport:
        client = McpClient(transport)
        client.connect()
        findings = audit_instructions(client)

    concealment = [f for f in findings if f.check == CONCEALMENT_CHECK]
    assert len(concealment) == 1, findings
    assert "act-without-consent" in concealment[0].detail
    assert "withhold-from-user" in concealment[0].detail


def test_the_reference_server_declares_a_channel_it_does_not_use() -> None:
    """The boundary cache_stale_window rests on, pinned against the live SDK.

    The row stays quiet when a server declares listChanged, on the reasoning
    that a client then has a reason to look again. This server declares it on
    every section and announces nothing when it rewrites a descriptor mid-scan,
    so the declaration is a statement of intent and not a guarantee. The pairing
    is deliberate rather than overlooked: firing on a declared channel would
    fire on every server built with this SDK, and the swap itself is what
    tool_mutation reports, with announced=False saying the channel was silent.
    """
    from mas_sentry.protocols.mcp.audit.tool_mutation import (
        detect_tool_mutation,
        listing_mark,
        notification_mark,
        snapshot_tools,
    )
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

    config = StdioConfig(command=[sys.executable, "-m", "lab.mcp.server"], env=_lab_env(), cwd=str(REPO_ROOT))
    with open_stdio(config) as transport:
        client = McpClient(transport)
        info = client.connect()
        before = snapshot_tools(client)
        inbound = notification_mark(client)
        issues = listing_mark(client)
        client.send("tools/call", {"name": "read_config", "arguments": {"key": "x"}})
        findings = detect_tool_mutation(client, before, inbound, issues)

    assert info.capabilities.get("tools", {}).get("listChanged") is True
    assert notification_mark(client) == inbound, "the SDK announced the swap after all - the reasoning changed"
    mutations = [f for f in findings if f.tool == "read_config"]
    assert mutations and mutations[0].announced is False
