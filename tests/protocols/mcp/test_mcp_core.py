# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Any

from mas_sentry.protocols.mcp.client import McpClient
from mas_sentry.protocols.mcp.fingerprint import fingerprint, known_cves_for
from mas_sentry.protocols.mcp.jsonrpc import (
    JsonRpcCodec,
    JsonRpcRequest,
    JsonRpcResponse,
)


class FakeTransport:
    """Scripted transport: returns canned responses for id-bearing requests."""

    def __init__(self, scripted: list[dict[str, Any]]) -> None:
        self.scripted = scripted
        self.calls: list[JsonRpcRequest] = []

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        self.calls.append(req)
        if req.id is None:
            return JsonRpcResponse(id=None)
        nxt = self.scripted.pop(0)
        return JsonRpcResponse.from_dict(nxt)


def test_jsonrpc_request_encode_minimum():
    req = JsonRpcCodec.request("ping", {}, 1)
    encoded = req.encode()
    assert b'"jsonrpc":"2.0"' in encoded
    assert b'"method":"ping"' in encoded
    assert b'"id":1' in encoded


def test_jsonrpc_notification_has_no_id():
    n = JsonRpcCodec.notification("notifications/initialized")
    assert n.id is None
    assert b'"id"' not in n.encode()


def test_jsonrpc_decode_malformed_returns_parse_error():
    r = JsonRpcResponse.decode(b"{not json")
    assert r.is_error
    assert r.error is not None
    assert r.error["code"] == -32700


def _git_server_script() -> list[dict[str, Any]]:
    return [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}, "prompts": {}},
                "serverInfo": {"name": "mcp-server-git", "version": "0.5.0"},
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "result": {"tools": [{"name": "git_init"}, {"name": "git_log"}]},
        },
        {"jsonrpc": "2.0", "id": 3, "result": {"prompts": []}},
        {"jsonrpc": "2.0", "id": 4, "result": {"resources": []}},
    ]


def test_enumerate_all_aggregates():
    t = FakeTransport(_git_server_script())
    client = McpClient(t)
    client.initialize()
    enum = client.enumerate_all()
    assert enum.total == 2
    assert [tool.name for tool in enum.tools] == ["git_init", "git_log"]


def test_fingerprint_full_flow():
    t = FakeTransport(_git_server_script())
    client = McpClient(t)
    fp = fingerprint(client, transport_name="stdio")
    assert fp.name == "mcp-server-git"
    assert fp.tool_count == 2
    assert fp.transport == "stdio"
    assert fp.tools_hash != ""
    assert "mcp-server-git" in fp.suspected_impls
    cves = [c for impl in fp.suspected_impls for c in known_cves_for(impl)]
    assert "CVE-2025-68143" in cves


def test_known_cves_for_is_case_insensitive():
    assert known_cves_for("MarkItDown") == known_cves_for("markitdown")
    assert known_cves_for("nonexistent") == []
