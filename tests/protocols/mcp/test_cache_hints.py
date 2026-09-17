# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEP-2549 freshness fields, captured from answers the scan already asked for.

The values ride inside listing results, so recording them costs nothing on the
wire - which is the whole reason this is worth auditing: a declaration read
from a response already in hand.
"""

from __future__ import annotations

from typing import Any

from mas_sentry.protocols.mcp.client import McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcRequest, JsonRpcResponse


class _PagingTransport:
    """Serves `pages` in order and counts what went out."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages
        self.sent: list[str] = []

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if req.id is None:
            return JsonRpcResponse(id=None)
        self.sent.append(req.method)
        page = self.pages[min(len([m for m in self.sent if m == req.method]) - 1, len(self.pages) - 1)]
        return JsonRpcResponse(id=req.id, result=page)


def _tool(name: str) -> dict[str, Any]:
    return {"name": name, "description": "", "inputSchema": {}}


def test_each_page_keeps_its_own_hint() -> None:
    """Pages are independently cacheable and may disagree, so they are kept apart."""
    transport = _PagingTransport(
        [
            {"tools": [_tool("a")], "nextCursor": "2", "ttlMs": 300000, "cacheScope": "public"},
            {"tools": [_tool("b")], "ttlMs": 5000, "cacheScope": "private"},
        ]
    )
    client = McpClient(transport)
    client.list_tools()

    hints = [(h.page, h.ttl_ms, h.cache_scope) for h in client.cache_hints]
    assert hints == [(0, 300000, "public"), (1, 5000, "private")]


def test_an_absent_field_is_not_recorded_as_zero() -> None:
    """Absent and zero are different statements, and only one of them is a defect.

    `ttlMs: 0` is the reference SDK default and means "immediately stale". No
    field at all is a MUST the server skipped; a client lands on 0 by rule
    rather than because the server said so. Merged, a conformant server and a
    silent one produce the same row.
    """
    transport = _PagingTransport([{"tools": [_tool("a")]}])
    client = McpClient(transport)
    client.list_tools()

    hint = client.cache_hints[0]
    assert hint.ttl_present is False
    assert hint.scope_present is False
    assert hint.ttl_ms is None


def test_a_zero_is_recorded_as_stated() -> None:
    transport = _PagingTransport([{"tools": [_tool("a")], "ttlMs": 0, "cacheScope": "private"}])
    client = McpClient(transport)
    client.list_tools()

    hint = client.cache_hints[0]
    assert hint.ttl_present is True
    assert hint.ttl_ms == 0


def test_values_are_kept_exactly_as_sent() -> None:
    """Repairing a malformed value here would leave the audit nothing to find."""
    transport = _PagingTransport([{"tools": [_tool("a")], "ttlMs": -1, "cacheScope": "shared"}])
    client = McpClient(transport)
    client.list_tools()

    hint = client.cache_hints[0]
    assert hint.ttl_ms == -1
    assert hint.cache_scope == "shared"


def test_capturing_hints_sends_nothing_extra() -> None:
    """Pinned by request count, not by reading the implementation.

    The point of this audit is that it is free. A capture that asked for its
    own copy of a listing would multiply the fan-out of every scan.
    """
    pages = [{"tools": [_tool("a")], "ttlMs": 1000, "cacheScope": "public"}]
    baseline = _PagingTransport(pages)
    McpClient(baseline).list_tools()

    counted = _PagingTransport(pages)
    client = McpClient(counted)
    client.list_tools()
    assert client.cache_hints, "nothing was captured"
    assert counted.sent == baseline.sent


def test_a_forced_relist_is_a_separate_walk() -> None:
    """The mutation audit enumerates twice; its pages are not the first walk's.

    Without the walk number, a second enumeration looks like more pages of the
    first one, and a scope that differs between walks reads as a violation of
    the per-request rule the SEP states - a finding invented out of our own
    bookkeeping.
    """
    transport = _PagingTransport([{"tools": [_tool("a")], "ttlMs": 1000, "cacheScope": "public"}])
    client = McpClient(transport)
    client.list_tools()
    client.relist_tools()

    walks = [(h.walk, h.page) for h in client.cache_hints if h.method == "tools/list"]
    assert walks == [(0, 0), (1, 0)]


def test_a_cached_listing_does_not_invent_a_walk() -> None:
    """Answered from cache means nothing arrived, so there is nothing to record."""
    transport = _PagingTransport([{"tools": [_tool("a")], "ttlMs": 1000, "cacheScope": "public"}])
    client = McpClient(transport)
    client.list_tools()
    client.list_tools()

    assert len([h for h in client.cache_hints if h.method == "tools/list"]) == 1
