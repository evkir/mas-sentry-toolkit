# SPDX-License-Identifier: AGPL-3.0-or-later
"""Streamable-HTTP transport state: session id and negotiated protocol revision.

The live rig in tests/integration/test_mcp_lab.py proves the behaviour end to
end; these pin the wire details it cannot isolate - which header goes out on
which request, and that the session is released on the way out.
"""

from __future__ import annotations

import json

import httpx
import pytest

from mas_sentry.protocols.mcp.client import McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec
from mas_sentry.protocols.mcp.transport_http import (
    PROTOCOL_VERSION_HEADER,
    SESSION_HEADER,
    HttpConfig,
    StreamableHttpTransport,
)

SESSION_ID = "sess-0123456789"
NEGOTIATED_VERSION = "2025-11-25"
URL = "http://mcp.test/mcp"


def _sse(payload: dict) -> str:
    return f"event: message\r\ndata: {json.dumps(payload)}\r\n\r\n"


class _Recorder:
    """Reference-shaped server: mints a session, then demands it back."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "DELETE":
            return httpx.Response(200)
        body = json.loads(request.content)
        if "id" not in body:
            # Notifications get an accepted-with-no-body answer, as the spec says.
            return httpx.Response(202)
        if body["method"] == "initialize":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream", SESSION_HEADER: SESSION_ID},
                text=_sse(
                    {
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {
                            "protocolVersion": NEGOTIATED_VERSION,
                            "capabilities": {},
                            "serverInfo": {"name": "ref", "version": "1.0.0"},
                        },
                    }
                ),
            )
        if request.headers.get(SESSION_HEADER) != SESSION_ID:
            return httpx.Response(
                400,
                json={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Bad Request: Missing session ID"},
                },
            )
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"tools": [{"name": "echo"}]}},
        )


@pytest.fixture
def rig() -> tuple[StreamableHttpTransport, _Recorder]:
    recorder = _Recorder()
    transport = StreamableHttpTransport(HttpConfig(url=URL))
    transport.open()
    transport._client = httpx.Client(transport=httpx.MockTransport(recorder))
    return transport, recorder


def test_initialize_carries_no_version_header(rig: tuple[StreamableHttpTransport, _Recorder]) -> None:
    """Nothing is negotiated yet, so nothing may be asserted about the revision."""
    transport, recorder = rig
    McpClient(transport).initialize()
    assert PROTOCOL_VERSION_HEADER not in recorder.requests[0].headers
    assert SESSION_HEADER not in recorder.requests[0].headers


def test_session_and_revision_are_adopted_from_the_response(
    rig: tuple[StreamableHttpTransport, _Recorder],
) -> None:
    """Both are read off the wire rather than assumed."""
    transport, _ = rig
    McpClient(transport).initialize()
    assert transport.session_id == SESSION_ID
    assert transport.protocol_version == NEGOTIATED_VERSION


def test_later_requests_carry_both_headers(rig: tuple[StreamableHttpTransport, _Recorder]) -> None:
    """The enumeration that used to come back empty now reaches the server."""
    transport, recorder = rig
    client = McpClient(transport)
    client.initialize()
    tools = client.list_tools()

    assert [t.name for t in tools] == ["echo"]
    last = recorder.requests[-1]
    assert last.headers[SESSION_HEADER] == SESSION_ID
    assert last.headers[PROTOCOL_VERSION_HEADER] == NEGOTIATED_VERSION


def test_a_stateless_server_is_not_handed_a_session(
    rig: tuple[StreamableHttpTransport, _Recorder],
) -> None:
    """No session header in the response means none goes out afterwards."""
    transport, _ = rig
    resp = transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))

    assert resp.is_error
    assert transport.session_id is None


def test_close_releases_the_server_side_session(
    rig: tuple[StreamableHttpTransport, _Recorder],
) -> None:
    """A scanner opens many sessions; leaving them to expire is our side effect."""
    transport, recorder = rig
    McpClient(transport).initialize()
    transport.close()

    deletes = [r for r in recorder.requests if r.method == "DELETE"]
    assert len(deletes) == 1
    assert deletes[0].headers[SESSION_HEADER] == SESSION_ID
    assert transport.session_id is None
