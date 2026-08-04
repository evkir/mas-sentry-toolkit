# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEP-2322: a suspended call is not a result, and must not read as a clean one."""

from typing import Any

from mas_sentry.protocols.mcp.audit.path_traversal import probe_path_traversal
from mas_sentry.protocols.mcp.audit.ssrf import probe_ssrf
from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse
from mas_sentry.protocols.mcp.runtime import _run_all_checks

_DISCOVER = {
    "result": {
        "capabilities": {"tools": {}},
        "cacheScope": "private",
        "resultType": "complete",
        "ttlMs": 0,
        "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
    }
}

_TOOLS = {
    "result": {
        "tools": [
            {
                "name": "fetch_url",
                "description": "fetch a url",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}},
            }
        ]
    }
}

_INPUT_REQUIRED = {
    "result": {
        "resultType": "input_required",
        "inputRequests": {
            "1": {"method": "elicitation/create", "params": {"mode": "url"}},
            "2": {"method": "sampling/createMessage", "params": {}},
        },
        "requestState": "opaque-token",
    }
}


class _SuspendingTransport:
    """Answers every tools/call with an input_required result."""

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


def _client() -> McpClient:
    return McpClient(
        _SuspendingTransport({DISCOVER_METHOD: _DISCOVER, "tools/list": _TOOLS, "tools/call": _INPUT_REQUIRED})
    )


def test_a_real_result_is_not_mistaken_for_a_suspended_one() -> None:
    resp = JsonRpcResponse(id=1, result={"resultType": "complete", "content": []})
    assert McpClient.input_required_of(resp) is None
    assert McpClient.input_required_of(JsonRpcResponse(id=1, result=None)) is None
    assert McpClient.input_required_of(JsonRpcResponse(id=1, error={"code": -32601})) is None


def test_suspended_call_is_recorded_with_what_the_server_asked_for() -> None:
    client = _client()
    client.send("tools/call", {"name": "fetch_url", "arguments": {"url": "http://x"}})
    assert len(client.input_required) == 1
    rec = client.input_required[0]
    assert rec.method == "tools/call"
    assert rec.kinds == ("elicitation/create", "sampling/createMessage")
    assert rec.has_request_state is True


def test_the_same_suspension_is_recorded_once() -> None:
    client = _client()
    for _ in range(3):
        client.send("tools/call", {"name": "fetch_url", "arguments": {"url": "http://x"}})
    assert len(client.input_required) == 1


def test_probes_report_nothing_and_the_scan_says_why() -> None:
    """The probes stay silent - the point is that the silence is now explained."""
    client = _client()
    assert probe_ssrf(client) == []
    assert probe_path_traversal(client) == []
    assert client.input_required, "the suspension must survive the probes that hit it"


def test_runtime_emits_the_gap_into_the_report() -> None:
    rows = _run_all_checks(_client(), transport="http", checks="all")
    gaps = [r for r in rows if r["check"] == "input_required"]
    assert len(gaps) == 1
    assert gaps[0]["severity"] == "MEDIUM"
    assert "tools/call" in gaps[0]["detail"]
    assert "requestState" in gaps[0]["detail"]


def test_missing_request_state_is_reported_as_missing() -> None:
    answers = {
        DISCOVER_METHOD: _DISCOVER,
        "tools/list": _TOOLS,
        "tools/call": {"result": {"resultType": "input_required"}},
    }
    client = McpClient(_SuspendingTransport(answers))
    client.send("tools/call", {"name": "fetch_url", "arguments": {}})
    rec = client.input_required[0]
    assert rec.kinds == ()
    assert rec.has_request_state is False
    assert "without a requestState" in rec.detail
    assert "no input request named" in rec.detail
