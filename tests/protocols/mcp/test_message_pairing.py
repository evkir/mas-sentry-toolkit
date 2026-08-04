# SPDX-License-Identifier: AGPL-3.0-or-later
"""Responses are matched by id; server-initiated traffic never counts as one.

The reference `everything` server emits notifications/tools/list_changed before
it answers initialize. Pairing by arrival order therefore shifted every later
answer by one: tools/list came back empty and prompts/list came back holding
the tools. Nothing raised, so the scan reported an empty inventory as a result.
"""

import json
import subprocess
import sys
from typing import Any

import httpx
import pytest

from mas_sentry.protocols.mcp.client import McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec, JsonRpcRequest
from mas_sentry.protocols.mcp.transport_http import HttpConfig, HttpSseTransport, _parse_sse, _select_answer
from mas_sentry.protocols.mcp.transport_stdio import MAX_MESSAGES_PER_SEND, StdioConfig, StdioTransport

_NOTIFICATION = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}


def _script(lines: list[dict[str, Any]]) -> list[str]:
    """A server that ignores input and dumps `lines` the moment it is spoken to."""
    payload = json.dumps(lines)
    code = (
        "import sys, json\n"
        f"out = json.loads({payload!r})\n"
        "first = True\n"
        "for _ in sys.stdin:\n"
        "    if first:\n"
        "        for item in out:\n"
        "            sys.stdout.write(json.dumps(item) + chr(10))\n"
        "        sys.stdout.flush()\n"
        "        first = False\n"
    )
    return [sys.executable, "-c", code]


def _transport(lines: list[dict[str, Any]], timeout: float = 5.0) -> StdioTransport:
    t = StdioTransport(StdioConfig(command=_script(lines), timeout=timeout))
    t.open()
    return t


def test_a_notification_ahead_of_the_answer_does_not_become_the_answer() -> None:
    lines = [_NOTIFICATION, {"jsonrpc": "2.0", "id": 1, "result": {"tools": ["a", "b"]}}]
    t = _transport(lines)
    try:
        resp = t.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        assert resp.result == {"tools": ["a", "b"]}
        assert t.notifications == [_NOTIFICATION]
    finally:
        t.close()


def test_a_response_for_another_request_is_held_not_consumed() -> None:
    """Out-of-order answers are legal; dropping one would desync the next read."""
    lines = [
        {"jsonrpc": "2.0", "id": 2, "result": {"second": True}},
        {"jsonrpc": "2.0", "id": 1, "result": {"first": True}},
    ]
    t = _transport(lines)
    try:
        first = t.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        assert first.result == {"first": True}
        second = t.send(JsonRpcCodec.request("prompts/list", {}, req_id=2))
        assert second.result == {"second": True}
    finally:
        t.close()


def test_an_endless_talker_costs_one_request_not_the_scan() -> None:
    t = _transport([_NOTIFICATION] * (MAX_MESSAGES_PER_SEND + 5), timeout=20.0)
    try:
        resp = t.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        assert resp.is_error
        assert "without answering tools/list" in str(resp.error)
    finally:
        t.close()


def test_an_unframeable_body_is_still_surfaced() -> None:
    t = _transport([])
    try:
        t._buf = bytearray(b"not json at all\n")
        resp = t.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        assert resp.is_error
    finally:
        t.close()


def test_the_client_enumerates_a_server_that_talks_first() -> None:
    """End to end: the defect showed up as an empty inventory, not an error."""
    lines = [
        _NOTIFICATION,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no discover"}},
        {"jsonrpc": "2.0", "id": 2, "result": {"serverInfo": {"name": "talker", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 3, "result": {"tools": [{"name": "echo"}]}},
    ]
    t = _transport(lines)
    try:
        client = McpClient(t)
        info = client.connect()
        assert info.name == "talker"
        assert [tool.name for tool in client.list_tools()] == ["echo"]
        assert client.enumeration_issues == []
    finally:
        t.close()


def test_sse_frames_are_all_decoded_not_just_the_first() -> None:
    body = (
        'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/message"}\n\n'
        'data: {"jsonrpc":"2.0","id":7,"result":{"ok":true}}\n'
    )
    answer, inbound = _select_answer(_parse_sse(body), 7)
    assert answer.result == {"ok": True}
    assert [n["method"] for n in inbound] == ["notifications/message"]


def test_a_stream_with_no_answer_is_an_error_not_a_notification() -> None:
    body = 'data: {"jsonrpc":"2.0","method":"notifications/message"}\n'
    answer, inbound = _select_answer(_parse_sse(body), 7)
    assert answer.is_error
    assert len(inbound) == 1


def test_http_transport_files_inbound_traffic(monkeypatch: pytest.MonkeyPatch) -> None:
    body = (
        'data: {"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n\n'
        'data: {"jsonrpc":"2.0","id":1,"result":{"tools":[]}}\n'
    )

    def fake_post(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        return httpx.Response(
            200,
            text=body,
            headers={"content-type": "text/event-stream"},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    t = HttpSseTransport(HttpConfig(url="http://localhost/mcp"))
    t.open()
    try:
        resp = t.send(JsonRpcRequest(method="tools/list", params={}, id=1))
        assert resp.result == {"tools": []}
        assert [n["method"] for n in t.notifications] == ["notifications/tools/list_changed"]
    finally:
        t.close()


def test_the_subprocess_script_helper_actually_runs() -> None:
    proc = subprocess.run(_script([{"ok": 1}]), input=b"x\n", capture_output=True, timeout=10)
    assert json.loads(proc.stdout) == {"ok": 1}
