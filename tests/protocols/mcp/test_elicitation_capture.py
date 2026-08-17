# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the server asked a human to do has to survive the parse, on both routes."""

from typing import Any

from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse

_DISCOVER = {
    "result": {
        "capabilities": {"tools": {}},
        "cacheScope": "private",
        "resultType": "complete",
        "ttlMs": 0,
        "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
    }
}


class _ScriptedTransport:
    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        answer = self.answers.get(body["method"], {"error": {"code": -32601, "message": "Method not found"}})
        if "error" in answer:
            return JsonRpcResponse(id=body.get("id"), error=answer["error"])
        return JsonRpcResponse(id=body.get("id"), result=answer.get("result", {}))

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _client(call_answer: dict[str, Any]) -> McpClient:
    return McpClient(_ScriptedTransport({DISCOVER_METHOD: _DISCOVER, "tools/call": call_answer}))


def _suspended(*requests: dict[str, Any]) -> dict[str, Any]:
    """An input_required result carrying the given requests, keyed as a server keys them."""
    return {
        "result": {
            "resultType": "input_required",
            "inputRequests": {str(i): req for i, req in enumerate(requests)},
            "requestState": "opaque",
        }
    }


_FORM = {
    "method": "elicitation/create",
    "params": {
        "mode": "form",
        "message": "need creds",
        "requestedSchema": {
            "type": "object",
            "properties": {
                "api_key": {"type": "string", "description": "Your API key"},
                "workspace": {"type": "string", "title": "Workspace"},
            },
            "required": ["api_key"],
        },
    },
}

_URL = {
    "method": "elicitation/create",
    "params": {"mode": "url", "message": "authorize", "url": "http://10.0.0.5/oauth"},
}


def test_a_form_elicitation_keeps_the_fields_it_would_collect() -> None:
    """The schema is the whole content; a record of the method alone says nothing."""
    client = _client(_suspended(_FORM))
    client.send("tools/call", {"name": "t", "arguments": {}})
    assert len(client.elicitations) == 1
    req = client.elicitations[0]
    assert req.mode == "form"
    assert req.method == "tools/call"
    assert req.fields == (("api_key", "Your API key"), ("workspace", "Workspace"))


def test_a_url_elicitation_keeps_the_address() -> None:
    client = _client(_suspended(_URL))
    client.send("tools/call", {"name": "t", "arguments": {}})
    assert client.elicitations[0].url == "http://10.0.0.5/oauth"
    assert client.elicitations[0].mode == "url"


def test_the_legacy_route_delivers_url_mode_as_an_error() -> None:
    """-32042 carries the same payload on the error path, and it was being dropped."""
    refusal = {
        "error": {
            "code": -32042,
            "message": "URL elicitation required",
            "data": {"elicitations": [{"mode": "url", "message": "authorize", "url": "http://evil.test/oauth"}]},
        }
    }
    client = _client(refusal)
    client.send("tools/call", {"name": "t", "arguments": {}})
    assert [e.url for e in client.elicitations] == ["http://evil.test/oauth"]


def test_an_elicitation_id_is_not_required_to_parse() -> None:
    """2026-07-28 removed the field; needing it would break against current servers."""
    without = {"mode": "url", "message": "m", "url": "https://ok.test/consent"}
    withid = {"mode": "url", "message": "m", "url": "https://ok.test/consent", "elicitationId": "auth-001"}
    for params in (without, withid):
        client = _client(_suspended({"method": "elicitation/create", "params": params}))
        client.send("tools/call", {"name": "t", "arguments": {}})
        assert client.elicitations[0].url == "https://ok.test/consent"


def test_a_schema_with_no_declared_mode_still_reads_as_form() -> None:
    """A 2025-line server predates modes and sends a schema with no mode at all."""
    legacy = {
        "method": "elicitation/create",
        "params": {"message": "m", "requestedSchema": {"properties": {"token": {"type": "string"}}}},
    }
    client = _client(_suspended(legacy))
    client.send("tools/call", {"name": "t", "arguments": {}})
    assert client.elicitations[0].mode == "form"
    assert client.elicitations[0].fields == (("token", ""),)


def test_sampling_and_roots_are_not_read_as_elicitations() -> None:
    """Neither asks a human anything, so neither belongs in the consent surface."""
    others = (
        {"method": "sampling/createMessage", "params": {"messages": []}},
        {"method": "roots/list", "params": {}},
    )
    client = _client(_suspended(*others))
    client.send("tools/call", {"name": "t", "arguments": {}})
    assert client.elicitations == []
    assert client.input_required[0].kinds == ("roots/list", "sampling/createMessage")


def test_the_same_elicitation_is_kept_once() -> None:
    client = _client(_suspended(_URL))
    for _ in range(3):
        client.send("tools/call", {"name": "t", "arguments": {}})
    assert len(client.elicitations) == 1


def test_a_hostile_schema_is_bounded() -> None:
    """The property list is the target's to write."""
    properties = {f"field{i}": {"type": "string"} for i in range(200)}
    wide = {
        "method": "elicitation/create",
        "params": {"mode": "form", "message": "m", "requestedSchema": {"properties": properties}},
    }
    client = _client(_suspended(wide))
    client.send("tools/call", {"name": "t", "arguments": {}})
    assert len(client.elicitations[0].fields) == 40


def test_an_unreadable_payload_records_nothing_and_raises_nothing() -> None:
    for broken in (
        {"error": {"code": -32042, "message": "no data"}},
        {"error": {"code": -32042, "message": "wrong shape", "data": {"elicitations": "not a list"}}},
        {"result": {"resultType": "input_required", "inputRequests": {"1": {"method": "elicitation/create"}}}},
    ):
        client = _client(broken)
        client.send("tools/call", {"name": "t", "arguments": {}})
        assert client.elicitations == []
