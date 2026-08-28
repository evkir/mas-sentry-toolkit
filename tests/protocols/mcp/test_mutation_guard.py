# SPDX-License-Identifier: AGPL-3.0-or-later
"""A listing that did not come back is not an inventory that emptied."""

from typing import Any

from mas_sentry.protocols.mcp.audit.tool_mutation import detect_tool_mutation, listing_mark
from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse

_DISCOVER = {
    "capabilities": {"tools": {}},
    "cacheScope": "private",
    "resultType": "complete",
    "ttlMs": 0,
    "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
}


class _Transport:
    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False
        self.notifications: list[dict[str, Any]] = []

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        if body["method"] == DISCOVER_METHOD:
            return JsonRpcResponse(id=body.get("id"), result=_DISCOVER)
        answer = self.answers.get(body["method"], {"result": {}})
        if "error" in answer:
            return JsonRpcResponse(id=body.get("id"), error=answer["error"])
        return JsonRpcResponse(id=body.get("id"), result=answer.get("result", {}))

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _client(answers: dict[str, Any]) -> McpClient:
    client = McpClient(_Transport(answers))
    client.connect()
    return client


def test_a_listing_that_failed_is_not_read_as_a_withdrawal() -> None:
    """Reproduced against the reference lab server, not imagined.

    One tool blocked on a DNS lookup, the single-threaded server queued the
    rest behind it, the re-enumeration timed out - and the scan reported five
    tools as withdrawn. An empty answer and no answer are the same mapping in
    Python and different facts about the target.
    """
    client = _client({"tools/list": {"error": {"code": -32000, "message": "no response"}}})
    mark = listing_mark(client)
    findings = detect_tool_mutation(client, {"read_config": "digest"}, 0, mark)
    assert [f.kind for f in findings] == ["mutation_inconclusive"]
    assert findings[0].severity == "MEDIUM"
    assert "does not claim to tell them apart" in findings[0].detail


def test_a_genuine_withdrawal_still_reports() -> None:
    """The guard must not swallow the real case: the listing came back, short."""
    client = _client({"tools/list": {"result": {"tools": []}}})
    findings = detect_tool_mutation(client, {"read_config": "digest"}, 0, listing_mark(client))
    assert [f.kind for f in findings] == ["tool_withdrawn"]


def test_a_descriptor_change_still_reports() -> None:
    tool = {"name": "read_config", "description": "poisoned now", "inputSchema": {}}
    client = _client({"tools/list": {"result": {"tools": [tool]}}})
    findings = detect_tool_mutation(client, {"read_config": "some-older-digest"}, 0, listing_mark(client))
    assert [f.kind for f in findings] == ["tool_mutation"]
