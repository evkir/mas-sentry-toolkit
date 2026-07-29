# SPDX-License-Identifier: AGPL-3.0-or-later
"""A refused listing must not read as an empty one.

`list_tools`, `list_prompts` and `list_resources` all return `[]` on failure,
which is the same value they return for a server that genuinely has none. Every
auditor downstream consumes those lists, so the difference decides whether a
scan reporting nothing means "clean" or "never looked".
"""

from __future__ import annotations

from typing import Any

from mas_sentry.protocols.mcp.client import METHOD_NOT_FOUND, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcRequest, JsonRpcResponse


class _RefusingTransport:
    """Answers initialize, then fails one named method and empties the rest."""

    def __init__(self, failing: dict[str, dict[str, Any]]) -> None:
        self.failing = failing

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if req.id is None:
            return JsonRpcResponse(id=None)
        if req.method == "initialize":
            return JsonRpcResponse(
                id=req.id,
                result={
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}, "prompts": {}, "resources": {}},
                    "serverInfo": {"name": "ref", "version": "1.0.0"},
                },
            )
        if req.method in self.failing:
            return JsonRpcResponse(id=req.id, error=self.failing[req.method])
        key = req.method.split("/")[0]
        return JsonRpcResponse(id=req.id, result={key: []})


def test_a_clean_server_records_nothing() -> None:
    """Genuinely empty inventories are not a gap."""
    client = McpClient(_RefusingTransport({}))
    client.initialize()
    client.enumerate_all()
    assert client.enumeration_issues == []


def test_a_refused_listing_is_recorded_with_its_code() -> None:
    """The code is the evidence: without it a refusal is indistinguishable from empty."""
    client = McpClient(_RefusingTransport({"tools/list": {"code": -32001, "message": "forbidden"}}))
    client.initialize()
    assert client.list_tools() == []

    issue = client.enumeration_issues[0]
    assert issue.method == "tools/list"
    assert issue.code == -32001
    assert "forbidden" in issue.detail


def test_an_unimplemented_method_is_informational() -> None:
    """A surface the server never built is expected, not a coverage failure."""
    client = McpClient(_RefusingTransport({"prompts/list": {"code": METHOD_NOT_FOUND, "message": "Method not found"}}))
    client.initialize()
    client.enumerate_all()

    issue = client.enumeration_issues[0]
    assert issue.method == "prompts/list"
    assert issue.severity == "INFO"


def test_a_refusal_outranks_an_absent_method() -> None:
    """Anything other than -32601 means the surface may exist and went unexamined."""
    client = McpClient(_RefusingTransport({"resources/list": {"code": 403, "message": "Forbidden"}}))
    client.initialize()
    client.enumerate_all()

    assert client.enumeration_issues[0].severity == "MEDIUM"


def test_repeated_calls_record_one_issue_per_method() -> None:
    """Auditors each call list_tools; the report must not repeat the same gap."""
    client = McpClient(_RefusingTransport({"tools/list": {"code": -32001, "message": "forbidden"}}))
    client.initialize()
    for _ in range(3):
        client.list_tools()

    assert len(client.enumeration_issues) == 1
