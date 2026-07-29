# SPDX-License-Identifier: AGPL-3.0-or-later
"""Paginated listings: the whole inventory, and a bound on hostile servers.

Reading only the first page is the quiet form of the empty-inventory defect.
Following cursors without a bound is the opposite failure: a server that never
stops issuing them turns a scan into a hang, which for a tool pointed at
untrusted infrastructure is a denial of service on the operator.
"""

from __future__ import annotations

from mas_sentry.protocols.mcp.client import MAX_LIST_PAGES, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcRequest, JsonRpcResponse


class _PagingTransport:
    """Serves `pages` in order, each already shaped as a tools/list result."""

    def __init__(self, pages: list[dict]) -> None:
        self.pages = pages
        self.cursors: list[str | None] = []

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if req.id is None:
            return JsonRpcResponse(id=None)
        params = req.params if isinstance(req.params, dict) else {}
        self.cursors.append(params.get("cursor"))
        page = self.pages[min(len(self.cursors) - 1, len(self.pages) - 1)]
        return JsonRpcResponse(id=req.id, result=page)


def _tool(name: str) -> dict:
    return {"name": name, "description": "", "inputSchema": {}}


def test_every_page_is_collected() -> None:
    """A tool past the first page is as interesting as one on it."""
    transport = _PagingTransport(
        [
            {"tools": [_tool("a"), _tool("b")], "nextCursor": "2"},
            {"tools": [_tool("c")], "nextCursor": "3"},
            {"tools": [_tool("d")]},
        ]
    )
    client = McpClient(transport)

    assert [t.name for t in client.list_tools()] == ["a", "b", "c", "d"]
    assert transport.cursors == [None, "2", "3"]
    assert client.enumeration_issues == []


def test_a_repeated_cursor_stops_the_walk_and_is_reported() -> None:
    """Returning the same cursor forever would otherwise spin us in place."""
    transport = _PagingTransport([{"tools": [_tool("a")], "nextCursor": "same"}])
    client = McpClient(transport)

    assert [t.name for t in client.list_tools()] == ["a", "a"]
    issue = client.enumeration_issues[0]
    assert issue.method == "tools/list"
    assert "repeated pagination cursor" in issue.detail
    assert issue.severity == "MEDIUM"


def test_an_endless_walk_is_bounded_and_reported() -> None:
    """A partial inventory must never be handed back as a complete one."""
    pages = [{"tools": [_tool(f"t{i}")], "nextCursor": str(i)} for i in range(MAX_LIST_PAGES + 5)]
    client = McpClient(_PagingTransport(pages))

    tools = client.list_tools()
    assert len(tools) == MAX_LIST_PAGES
    assert "did not terminate" in client.enumeration_issues[0].detail


def test_a_single_page_sends_no_cursor() -> None:
    """The first request carries no cursor, per the spec."""
    transport = _PagingTransport([{"tools": [_tool("a")]}])
    McpClient(transport).list_tools()

    assert transport.cursors == [None]
