# SPDX-License-Identifier: AGPL-3.0-or-later
"""-32021: the server refused rather than elicited, and the probe never ran."""

from typing import Any

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

_REFUSED = {
    "error": {
        "code": -32021,
        "message": "Client did not declare the sampling capability required by resolver",
        "data": {"requiredCapabilities": {"sampling": {"tools": {}}}},
    }
}


class _RefusingTransport:
    """Answers every tools/call with -32021."""

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


def _client(call_answer: dict[str, Any] | None = None) -> McpClient:
    answers = {DISCOVER_METHOD: _DISCOVER, "tools/list": _TOOLS, "tools/call": call_answer or _REFUSED}
    return McpClient(_RefusingTransport(answers))


def test_the_refusal_is_recorded_with_what_the_server_wanted() -> None:
    client = _client()
    client.send("tools/call", {"name": "fetch_url", "arguments": {"url": "http://x"}})
    assert len(client.capability_gaps) == 1
    gap = client.capability_gaps[0]
    assert gap.method == "tools/call"
    assert gap.capabilities == ("sampling.tools",)
    assert gap.severity == "MEDIUM"


def test_another_error_is_not_read_as_a_capability_refusal() -> None:
    """The detector has to stay silent on every other code, or it fires always."""
    client = _client({"error": {"code": -32602, "message": "Invalid params"}})
    client.send("tools/call", {"name": "fetch_url", "arguments": {}})
    assert client.capability_gaps == []


def test_a_refusal_with_no_payload_still_records_the_method() -> None:
    """A server that names nothing still took the method out of coverage."""
    client = _client({"error": {"code": -32021, "message": "not declared"}})
    client.send("tools/call", {"name": "fetch_url", "arguments": {}})
    assert client.capability_gaps[0].capabilities == ()
    assert "no capability named" in client.capability_gaps[0].detail


def test_a_hostile_capability_payload_is_bounded() -> None:
    """The payload is written by the target; the walk over it cannot be unbounded."""
    deep: dict[str, Any] = {}
    node = deep
    for i in range(40):
        node[f"level{i}"] = {}
        node = node[f"level{i}"]
    refusal = {"error": {"code": -32021, "message": "x", "data": {"requiredCapabilities": deep}}}
    client = _client(refusal)
    client.send("tools/call", {"name": "fetch_url", "arguments": {}})
    paths = client.capability_gaps[0].capabilities
    assert len(paths) == 1
    assert paths[0].count(".") <= 4


def test_the_same_refusal_is_recorded_once() -> None:
    client = _client()
    for _ in range(3):
        client.send("tools/call", {"name": "fetch_url", "arguments": {"url": "http://x"}})
    assert len(client.capability_gaps) == 1


def test_a_refused_probe_never_reads_as_a_verdict() -> None:
    """The probe must claim nothing about a tool it never reached.

    Every payload comes back refused, so no attempt may carry the confirming
    status - and the refusal has to survive the probe run, or the report shows
    a tool that was audited and found clean.
    """
    client = _client()
    assert [f for f in probe_ssrf(client) if f.status == "OK"] == []
    assert client.capability_gaps, "the refusal must survive the probes that hit it"


def test_runtime_emits_the_gap_into_the_report() -> None:
    rows = _run_all_checks(_client(), transport="http", checks="all")
    gaps = [r for r in rows if r["check"] == "capability_required"]
    assert len(gaps) == 1
    assert gaps[0]["severity"] == "MEDIUM"
    assert "sampling.tools" in gaps[0]["detail"]
    assert "reached no result" in gaps[0]["detail"]
