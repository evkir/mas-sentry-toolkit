# SPDX-License-Identifier: AGPL-3.0-or-later
"""SEP-2663: a task handle is not a result, and must not read as a clean one."""

from typing import Any

from mas_sentry.protocols.mcp.audit.path_traversal import probe_arg_injection, probe_path_traversal
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
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}, "path": {"type": "string"}},
                },
            }
        ]
    }
}

_TASK = {
    "result": {
        "resultType": "task",
        "task": {"taskId": "t-1", "status": "working", "ttlMs": 600000, "pollIntervalMs": 1000},
    }
}

_COMPLETE = {"result": {"resultType": "complete", "content": [{"type": "text", "text": "ok"}]}}


class _Transport:
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


def _deferring_client() -> McpClient:
    return McpClient(_Transport({DISCOVER_METHOD: _DISCOVER, "tools/list": _TOOLS, "tools/call": _TASK}))


def _answering_client() -> McpClient:
    return McpClient(_Transport({DISCOVER_METHOD: _DISCOVER, "tools/list": _TOOLS, "tools/call": _COMPLETE}))


def test_a_real_result_is_not_mistaken_for_a_task() -> None:
    assert McpClient.task_of(JsonRpcResponse(id=1, result={"resultType": "complete", "content": []})) is None
    assert McpClient.task_of(JsonRpcResponse(id=1, result=None)) is None
    assert McpClient.task_of(JsonRpcResponse(id=1, error={"code": -32601})) is None


def test_a_suspended_call_is_not_mistaken_for_a_task() -> None:
    suspended = JsonRpcResponse(id=1, result={"resultType": "input_required", "inputRequests": {}})
    assert McpClient.task_of(suspended) is None


def test_deferred_call_is_recorded_with_the_handle_the_server_sent() -> None:
    client = _deferring_client()
    client.send("tools/call", {"name": "fetch_url", "arguments": {}})
    assert len(client.deferred_tasks) == 1
    rec = client.deferred_tasks[0]
    assert rec.method == "tools/call"
    assert rec.status == "working"
    assert rec.has_task_id is True
    assert rec.ttl_ms == 600000
    assert rec.poll_interval_ms == 1000
    assert "did not run" in rec.detail
    assert "io.modelcontextprotocol/tasks" in rec.detail


def test_one_row_per_method_however_many_probes_were_deferred() -> None:
    client = _deferring_client()
    for _ in range(5):
        client.send("tools/call", {"name": "fetch_url", "arguments": {}})
    assert len(client.deferred_tasks) == 1


def test_a_handle_without_fields_is_reported_as_missing_them() -> None:
    answers = {DISCOVER_METHOD: _DISCOVER, "tools/list": _TOOLS, "tools/call": {"result": {"resultType": "task"}}}
    client = McpClient(_Transport(answers))
    client.send("tools/call", {"name": "fetch_url", "arguments": {}})
    rec = client.deferred_tasks[0]
    assert rec.has_task_id is False
    assert rec.ttl_ms is None
    assert "no taskId" in rec.detail
    assert "ttl unstated" in rec.detail


def test_probes_find_nothing_and_the_deferral_survives_them() -> None:
    client = _deferring_client()
    assert [f for f in probe_ssrf(client) if f.status == "OK"] == []
    assert probe_path_traversal(client) == []
    assert [f for f in probe_arg_injection(client) if f.confirmed] == []
    assert client.deferred_tasks, "the deferral must survive the probes that hit it"


def test_runtime_emits_the_gap_into_the_report() -> None:
    rows = _run_all_checks(_deferring_client(), transport="http", checks="all")
    gaps = [r for r in rows if r["check"] == "task_undeclared"]
    assert len(gaps) == 1
    assert gaps[0]["severity"] == "MEDIUM"
    assert "tools/call" in gaps[0]["detail"]


def test_a_server_that_answers_normally_produces_no_row() -> None:
    rows = _run_all_checks(_answering_client(), transport="http", checks="all")
    assert [r for r in rows if r["check"] == "task_undeclared"] == []
