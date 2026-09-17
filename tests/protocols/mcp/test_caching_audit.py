# SPDX-License-Identifier: AGPL-3.0-or-later
"""The SEP-2549 declaration is read for what it says, not repaired.

Every case here is built from values a target sent, because that is where the
module gets them: the pages ride in with the listings, and the audit adds no
request of its own.
"""

from __future__ import annotations

from typing import Any

from mas_sentry.protocols.mcp.audit.caching import (
    SCOPE_INVALID_CHECK,
    SCOPE_SPLIT_CHECK,
    TTL_INVALID_CHECK,
    TTL_MISSING_CHECK,
    audit_caching,
)
from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse
from mas_sentry.protocols.mcp.runtime import _run_all_checks

_MODERN_DISCOVER: dict[str, Any] = {
    "protocolVersion": "2026-07-28",
    "capabilities": {"tools": {}},
    "ttlMs": 0,
    "cacheScope": "private",
    "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
}


class _Transport:
    """Answers discover from a fixed payload and every listing from a page script."""

    def __init__(self, discover: dict[str, Any], pages: dict[str, list[dict[str, Any]]]) -> None:
        self.discover = discover
        self.pages = pages
        self.seen: dict[str, int] = {}
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        method = body["method"]
        if body.get("id") is None:
            return JsonRpcResponse(id=None)
        if method == DISCOVER_METHOD:
            return JsonRpcResponse(id=body["id"], result=self.discover)
        script = self.pages.get(method)
        if script is None:
            return JsonRpcResponse(id=body["id"], error={"code": -32601, "message": "Method not found"})
        index = min(self.seen.get(method, 0), len(script) - 1)
        self.seen[method] = index + 1
        return JsonRpcResponse(id=body["id"], result=script[index])

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _tool(name: str) -> dict[str, Any]:
    return {"name": name, "description": "", "inputSchema": {}}


def _client(pages: list[dict[str, Any]], discover: dict[str, Any] | None = None) -> McpClient:
    client = McpClient(_Transport(dict(discover or _MODERN_DISCOVER), {"tools/list": pages}))
    client.connect()
    client.list_tools()
    return client


def _checks(client: McpClient) -> list[str]:
    return [f.check for f in audit_caching(client)]


def test_a_conformant_declaration_produces_nothing() -> None:
    """ttlMs 0 and a stated scope are what both reference SDKs send by default."""
    client = _client([{"tools": [_tool("a")], "ttlMs": 0, "cacheScope": "private"}])
    assert audit_caching(client) == []


def test_an_absent_ttl_is_a_skipped_must() -> None:
    """The revision requires the field; a client reaching 0 by rule is not the server speaking."""
    client = _client([{"tools": [_tool("a")], "cacheScope": "private"}])
    findings = audit_caching(client)
    assert [f.check for f in findings] == [TTL_MISSING_CHECK]
    assert findings[0].severity == "LOW"
    assert "tools/list" in findings[0].detail


def test_a_negative_ttl_is_reported_as_sent() -> None:
    """Repairing the value here would leave the audit with nothing to report."""
    client = _client([{"tools": [_tool("a")], "ttlMs": -5000, "cacheScope": "private"}])
    findings = [f for f in audit_caching(client) if f.check == TTL_INVALID_CHECK]
    assert len(findings) == 1
    assert "-5000" in findings[0].detail


def test_a_ttl_of_the_wrong_type_is_reported_with_its_type() -> None:
    """A string where a number belongs is a fact about the target, not a parse error."""
    client = _client([{"tools": [_tool("a")], "ttlMs": "3600", "cacheScope": "private"}])
    findings = [f for f in audit_caching(client) if f.check == TTL_INVALID_CHECK]
    assert len(findings) == 1
    assert "'3600'" in findings[0].detail and "str" in findings[0].detail


def test_a_boolean_ttl_is_not_read_as_a_number() -> None:
    """bool is an int in Python and nowhere else; the wire said true, not 1."""
    client = _client([{"tools": [_tool("a")], "ttlMs": True, "cacheScope": "private"}])
    findings = [f for f in audit_caching(client) if f.check == TTL_INVALID_CHECK]
    assert len(findings) == 1
    assert "bool" in findings[0].detail


def test_an_undefined_scope_is_reported() -> None:
    """The empty string is the shape a merging proxy emits, and strict clients reject the listing."""
    client = _client([{"tools": [_tool("a")], "ttlMs": 0, "cacheScope": ""}])
    findings = [f for f in audit_caching(client) if f.check == SCOPE_INVALID_CHECK]
    assert len(findings) == 1
    assert "''" in findings[0].detail


def test_two_scopes_in_one_walk_contradict_the_sep() -> None:
    """One scope per listing request. The pages compared came from one walk we performed."""
    client = _client(
        [
            {"tools": [_tool("a")], "nextCursor": "2", "ttlMs": 60000, "cacheScope": "public"},
            {"tools": [_tool("b")], "ttlMs": 60000, "cacheScope": "private"},
        ]
    )
    findings = [f for f in audit_caching(client) if f.check == SCOPE_SPLIT_CHECK]
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert "page 0" in findings[0].detail and "page 1" in findings[0].detail


def test_a_scope_present_on_one_page_and_absent_on_the_next_is_a_split() -> None:
    """Absent is not private: the pages still do not carry the same scope."""
    client = _client(
        [
            {"tools": [_tool("a")], "nextCursor": "2", "ttlMs": 0, "cacheScope": "private"},
            {"tools": [_tool("b")], "ttlMs": 0},
        ]
    )
    assert SCOPE_SPLIT_CHECK in _checks(client)


def test_two_walks_disagreeing_is_not_a_split() -> None:
    """The MUST is about one request. A server may answer a later walk differently."""
    client = _client(
        [
            {"tools": [_tool("a")], "ttlMs": 0, "cacheScope": "public"},
            {"tools": [_tool("a")], "ttlMs": 0, "cacheScope": "private"},
        ]
    )
    client._list_paged("tools/list", "tools", refresh=True)
    assert SCOPE_SPLIT_CHECK not in _checks(client)


def test_a_legacy_target_is_not_asked_for_fields_its_revision_lacks() -> None:
    """Silence about caching is a fact only where the protocol asked for speech."""
    client = _client(
        [{"tools": [_tool("a")]}],
        discover={**_MODERN_DISCOVER, "protocolVersion": "2025-11-25"},
    )
    assert audit_caching(client) == []


def test_the_audit_sends_no_request_of_its_own() -> None:
    """The values were already in hand; reading them costs nothing on the wire."""
    client = _client([{"tools": [_tool("a")]}])
    transport = client.transport
    assert isinstance(transport, _Transport)
    before = dict(transport.seen)
    audit_caching(client)
    assert transport.seen == before


def test_the_row_reaches_the_report() -> None:
    """A detector nothing calls is a detector that never fires in the field."""
    client = _client([{"tools": [_tool("a")], "ttlMs": -1, "cacheScope": "private"}])
    rows = _run_all_checks(client, transport="http", checks="all")
    assert TTL_INVALID_CHECK in {row["check"] for row in rows}
