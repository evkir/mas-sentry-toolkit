# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Any

from mas_sentry.protocols.mcp.audit.path_traversal import (
    _first_path_param,
    _first_string_param,
    probe_path_traversal,
)
from mas_sentry.protocols.mcp.audit.ssrf import _ssrf_indicator, probe_ssrf
from mas_sentry.protocols.mcp.client import McpClient, ToolDef
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcRequest, JsonRpcResponse


class _ScriptedTransport:
    """Returns canned responses; records every outgoing request."""

    def __init__(self, scripted: list[dict[str, Any]]) -> None:
        self.scripted = scripted
        self.calls: list[JsonRpcRequest] = []

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        self.calls.append(req)
        if req.id is None:
            return JsonRpcResponse(id=None)
        nxt = self.scripted.pop(0) if self.scripted else {"jsonrpc": "2.0", "id": req.id, "result": {}}
        return JsonRpcResponse.from_dict(nxt)


# ---- ssrf: indicator unit tests -------------------------------------------


def test_ssrf_indicator_aws_imds():
    body = "ami-id\nami-12345\nblock-device-mapping"
    assert _ssrf_indicator("http://169.254.169.254/latest/meta-data/", body)


def test_ssrf_indicator_etc_passwd():
    body = "root:x:0:0:root:/root:/bin/bash"
    assert _ssrf_indicator("file:///etc/passwd", body)


def test_ssrf_indicator_no_match():
    assert not _ssrf_indicator("http://example.com/", "harmless body")


# ---- schema helpers -------------------------------------------------------


def test_path_param_detection():
    schema = {"properties": {"file_path": {"type": "string"}, "max_lines": {"type": "integer"}}}
    assert _first_path_param(schema) == "file_path"


def test_string_param_detection():
    schema = {"properties": {"name": {"type": "string"}, "count": {"type": "integer"}}}
    assert _first_string_param(schema) == "name"


def test_path_param_none_on_empty_schema():
    assert _first_path_param(None) is None
    assert _first_path_param({}) is None


# ---- ssrf probe: filter logic ---------------------------------------------


def test_probe_ssrf_drops_silent_ok():
    """OK response without indicator content must NOT produce a finding."""
    tools = [ToolDef(name="fetch_url", description="", input_schema={})]
    # 5 sensitive URLs x scripted "harmless" results
    scripted = [{"jsonrpc": "2.0", "id": i + 1, "result": "nothing sensitive here"} for i in range(5)]
    client = McpClient(_ScriptedTransport(scripted))  # type: ignore[arg-type]
    # Inject tool list without calling initialize
    client.list_tools = lambda: tools  # type: ignore[method-assign]
    findings = probe_ssrf(client)
    assert findings == []


def test_probe_ssrf_keeps_confirmed_imds():
    tools = [ToolDef(name="http_get", description="", input_schema={})]
    scripted = [
        {"jsonrpc": "2.0", "id": 1, "result": "ami-id ami-12345 instance-id i-abc"},
    ] + [{"jsonrpc": "2.0", "id": i + 2, "result": "boring"} for i in range(4)]
    client = McpClient(_ScriptedTransport(scripted))  # type: ignore[arg-type]
    client.list_tools = lambda: tools  # type: ignore[method-assign]
    findings = probe_ssrf(client)
    assert len(findings) == 1
    assert findings[0].status == "OK"
    assert "169.254.169.254" in findings[0].url


# ---- path traversal probe: filter logic -----------------------------------


def test_probe_path_traversal_drops_silent_ok():
    tools = [
        ToolDef(
            name="read_file",
            description="",
            input_schema={"properties": {"file_path": {"type": "string"}}},
        )
    ]
    scripted = [{"jsonrpc": "2.0", "id": i + 1, "result": "not sensitive"} for i in range(3)]
    client = McpClient(_ScriptedTransport(scripted))  # type: ignore[arg-type]
    client.list_tools = lambda: tools  # type: ignore[method-assign]
    findings = probe_path_traversal(client)
    assert findings == []


def test_probe_path_traversal_keeps_confirmed_passwd():
    tools = [
        ToolDef(
            name="read_file",
            description="",
            input_schema={"properties": {"file_path": {"type": "string"}}},
        )
    ]
    scripted = [
        {"jsonrpc": "2.0", "id": 1, "result": "root:x:0:0:root:/root:/bin/bash"},
        {"jsonrpc": "2.0", "id": 2, "result": "nothing"},
        {"jsonrpc": "2.0", "id": 3, "result": "nothing"},
    ]
    client = McpClient(_ScriptedTransport(scripted))  # type: ignore[arg-type]
    client.list_tools = lambda: tools  # type: ignore[method-assign]
    findings = probe_path_traversal(client)
    assert len(findings) == 1
    assert findings[0].confirmed is True
