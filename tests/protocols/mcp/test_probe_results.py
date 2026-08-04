# SPDX-License-Identifier: AGPL-3.0-or-later
"""Probe behaviour against structured tool results and tool-level errors.

These probes call tools/call directly through the codec, so a stub transport is
enough to exercise them offline. The cases that matter are the ones that used to
be invisible: a refusal delivered as isError inside a successful response, and
an indicator carried in a base64 content block or past a truncation boundary.
"""

from __future__ import annotations

import base64
from typing import Any

from mas_sentry.protocols.mcp.audit.path_traversal import probe_path_traversal
from mas_sentry.protocols.mcp.audit.ssrf import probe_ssrf
from mas_sentry.protocols.mcp.client import ToolDef
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec, JsonRpcResponse


class _StubTransport:
    def __init__(self, result: Any = None, error: dict[str, Any] | None = None) -> None:
        self._result = result
        self._error = error
        self.sent = 0

    def send(self, _req: Any) -> JsonRpcResponse:
        self.sent += 1
        return JsonRpcResponse(id=1, result=self._result, error=self._error)


class _StubClient:
    def __init__(self, tools: list[ToolDef], transport: _StubTransport) -> None:
        self._tools = tools
        self.transport = transport
        self._id = 0

    def list_tools(self) -> list[ToolDef]:
        return self._tools

    def next_id(self) -> int:
        self._id += 1
        return self._id

    def send(self, method: str, params: dict[str, Any] | None = None) -> JsonRpcResponse:
        """Mirror the real client: build the request, hand it to the transport.

        The audits call client.send() rather than client.transport.send() so the
        stateless protocol envelope is added in one place. These stubs keep the
        transport visible because the tests assert on what reached the wire.
        """
        return self.transport.send(JsonRpcCodec.request(method, params, req_id=self.next_id()))


def _text_result(text: str, is_error: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if is_error:
        out["isError"] = True
    return out


_FETCH_TOOL = [ToolDef(name="fetch_url", description="fetch a url")]
_READ_TOOL = [ToolDef(name="read_file", input_schema={"properties": {"path": {"type": "string"}}})]


# --- SSRF ---


def test_ssrf_tool_level_refusal_is_recorded_as_denied() -> None:
    # The refusal arrives inside a successful response, which is what the spec
    # mandates. Previously it fell through and was silently dropped, so a guarded
    # server looked identical to one that answered with nothing.
    client = _StubClient(_FETCH_TOOL, _StubTransport(_text_result("blocked: SSRF guard", is_error=True)))
    out = probe_ssrf(client)  # type: ignore[arg-type]
    assert out, "a tool-level refusal must be reported"
    assert {f.status for f in out} == {"DENIED"}
    assert "SSRF guard" in out[0].evidence


def test_ssrf_protocol_error_still_denied() -> None:
    client = _StubClient(_FETCH_TOOL, _StubTransport(error={"code": -32602, "message": "bad url"}))
    out = probe_ssrf(client)  # type: ignore[arg-type]
    assert {f.status for f in out} == {"DENIED"}


def test_ssrf_indicator_in_text_block_confirms() -> None:
    client = _StubClient(_FETCH_TOOL, _StubTransport(_text_result("root:x:0:0:root:/root:/bin/bash")))
    out = probe_ssrf(client)  # type: ignore[arg-type]
    hits = [f for f in out if f.status == "OK"]
    assert hits and any("passwd" in f.url for f in hits)


def test_ssrf_indicator_inside_base64_block_confirms() -> None:
    # A result delivered as an image/resource blob hides its bytes from any
    # substring match against the raw response object.
    blob = base64.b64encode(b"root:x:0:0:root:/root:/bin/bash").decode()
    client = _StubClient(_FETCH_TOOL, _StubTransport({"content": [{"type": "image", "data": blob}]}))
    out = probe_ssrf(client)  # type: ignore[arg-type]
    assert [f for f in out if f.status == "OK"], "base64 content must be decoded before matching"


def test_ssrf_indicator_past_the_old_truncation_still_confirms() -> None:
    # The previous implementation matched against the first 400 characters of a
    # repr, so an indicator further in was missed.
    padded = "x" * 900 + " root:x:0:0"
    client = _StubClient(_FETCH_TOOL, _StubTransport(_text_result(padded)))
    out = probe_ssrf(client)  # type: ignore[arg-type]
    assert [f for f in out if f.status == "OK"]


def test_ssrf_clean_response_reports_nothing() -> None:
    client = _StubClient(_FETCH_TOOL, _StubTransport(_text_result("<html>hello</html>")))
    assert probe_ssrf(client) == []  # type: ignore[arg-type]


def test_ssrf_skips_tools_that_do_not_fetch() -> None:
    transport = _StubTransport(_text_result("root:x:0:0"))
    client = _StubClient([ToolDef(name="add_numbers")], transport)
    assert probe_ssrf(client) == []  # type: ignore[arg-type]
    assert transport.sent == 0


# --- path traversal ---


def test_traversal_tool_level_refusal_is_reported_unconfirmed() -> None:
    client = _StubClient(_READ_TOOL, _StubTransport(_text_result("path escapes root", is_error=True)))
    out = probe_path_traversal(client)  # type: ignore[arg-type]
    assert out
    assert all(not f.confirmed for f in out)
    assert "tool refused" in out[0].note


def test_traversal_confirmed_from_text_block() -> None:
    client = _StubClient(_READ_TOOL, _StubTransport(_text_result("root:x:0:0:root:/root")))
    out = probe_path_traversal(client)  # type: ignore[arg-type]
    assert any(f.confirmed for f in out)


def test_traversal_confirmed_from_embedded_resource() -> None:
    result = {"content": [{"type": "resource", "resource": {"uri": "file:///etc/passwd", "text": "root:x:0:0"}}]}
    client = _StubClient(_READ_TOOL, _StubTransport(result))
    out = probe_path_traversal(client)  # type: ignore[arg-type]
    assert any(f.confirmed for f in out)


def test_traversal_clean_response_reports_nothing() -> None:
    client = _StubClient(_READ_TOOL, _StubTransport(_text_result("file not found")))
    assert probe_path_traversal(client) == []  # type: ignore[arg-type]
