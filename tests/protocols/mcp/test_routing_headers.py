# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mcp-Method / Mcp-Name must mirror the body, and a rejection must survive."""

import httpx

from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec
from mas_sentry.protocols.mcp.transport_http import (
    METHOD_HEADER,
    NAME_HEADER,
    _error_response,
    routing_headers,
)


def test_plain_method_carries_only_the_method_header():
    h = routing_headers(JsonRpcCodec.request("tools/list", {}))
    assert h == {METHOD_HEADER: "tools/list"}


def test_tools_call_mirrors_the_tool_name():
    h = routing_headers(JsonRpcCodec.request("tools/call", {"name": "read_file", "arguments": {}}))
    assert h[NAME_HEADER] == "read_file"


def test_resources_read_routes_on_uri_not_name():
    """The reference SDK keys resources/read on `uri`; using `name` is a -32020."""
    h = routing_headers(JsonRpcCodec.request("resources/read", {"uri": "file://lab/policy"}))
    assert h[NAME_HEADER] == "file://lab/policy"


def test_prompts_get_mirrors_the_prompt_name():
    h = routing_headers(JsonRpcCodec.request("prompts/get", {"name": "summarize"}))
    assert h[NAME_HEADER] == "summarize"


def test_absent_name_omits_the_header_rather_than_sending_an_empty_one():
    h = routing_headers(JsonRpcCodec.request("tools/call", {"arguments": {}}))
    assert NAME_HEADER not in h


def test_a_rejection_keeps_the_jsonrpc_error_the_server_sent():
    """-32022 carries the supported revisions; an HTTP status carries nothing.

    Replacing the body with the bare status discards exactly the payload a
    version-aware client needs in order to fall back.
    """
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {
            "code": -32022,
            "message": "Unsupported protocol version",
            "data": {"supported": ["2026-07-28"], "requested": "2099-01-01"},
        },
    }
    r = httpx.Response(400, json=body, headers={"content-type": "application/json"})
    resp = _error_response(JsonRpcCodec.request("tools/list", {}), r)
    assert resp.error is not None
    assert resp.error["code"] == -32022
    assert resp.error["data"]["supported"] == ["2026-07-28"]


def test_a_rejection_with_no_body_still_reports_the_status():
    """A proxy error page is not a protocol error and must not be reported as one."""
    r = httpx.Response(503, text="upstream down")
    resp = _error_response(JsonRpcCodec.request("tools/list", {}), r)
    assert resp.error is not None
    assert resp.error["code"] == 503
