# SPDX-License-Identifier: AGPL-3.0-or-later
"""A server must reject a request whose routing headers contradict its body."""

from typing import Any

from mas_sentry.protocols.mcp.audit.header_desync import probe_header_desync
from mas_sentry.protocols.mcp.client import McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse
from mas_sentry.protocols.mcp.transport_http import METHOD_HEADER, NAME_HEADER


class _HeaderTransport:
    """Records the headers of each probe and answers with a scripted verdict."""

    supports_headers = True

    def __init__(self, verdict: str = "reject") -> None:
        self.verdict = verdict
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.probes: list[dict[str, str]] = []
        self.bodies: list[dict[str, Any]] = []

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        if body["method"] == "server/discover":
            return JsonRpcResponse(id=body.get("id"), result={"capabilities": {}})
        return JsonRpcResponse(id=body.get("id"), result={})

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        body = req.to_dict()
        self.probes.append(dict(overrides))
        self.bodies.append(body)
        if self.verdict == "accept":
            return JsonRpcResponse(id=body.get("id"), result={"content": []})
        if self.verdict == "unrelated":
            return JsonRpcResponse(id=body.get("id"), error={"code": -32601, "message": "Method not found"})
        return JsonRpcResponse(
            id=body.get("id"),
            error={"code": -32020, "message": "Mcp-Method header does not match the request body method"},
        )


class _StdioLikeTransport:
    supports_headers = False
    emit_routing_headers = False
    protocol_version: str | None = None

    def send(self, req: Any) -> JsonRpcResponse:
        return JsonRpcResponse(id=1, result={"capabilities": {}})


def _client(transport: Any) -> McpClient:
    client = McpClient(transport)
    client.connect()
    return client


def test_a_conforming_server_rejects_every_probe():
    """The reference SDK answers -32020; nothing here should be reported."""
    t = _HeaderTransport("reject")
    findings = probe_header_desync(_client(t), tool_name="read_file", resource_uri="file://lab/policy")
    assert {f.status for f in findings} == {"rejected"}


def test_a_permissive_server_is_reported_on_every_probe():
    t = _HeaderTransport("accept")
    findings = probe_header_desync(_client(t), tool_name="read_file", resource_uri="file://lab/policy")
    assert {f.status for f in findings} == {"accepted"}
    assert {f.probe for f in findings} == {
        "method_mismatch",
        "name_mismatch",
        "uri_mismatch",
        "absent_method_header",
    }


def test_an_unrelated_refusal_is_inconclusive_not_a_pass():
    """-32601 means the probe never reached the header check.

    Recording that as "rejected" would credit the server with a validation it
    may not perform, which is the failure mode this whole audit exists to avoid.
    """
    t = _HeaderTransport("unrelated")
    findings = probe_header_desync(_client(t), tool_name="read_file")
    assert {f.status for f in findings} == {"inconclusive"}


def test_the_method_probe_claims_a_listing_while_calling_a_tool():
    t = _HeaderTransport("accept")
    probe_header_desync(_client(t), tool_name="read_file")
    assert t.probes[0][METHOD_HEADER] == "tools/list"
    assert t.bodies[0]["method"] == "tools/call"


def test_the_name_probe_keeps_the_method_and_changes_only_the_name():
    t = _HeaderTransport("accept")
    probe_header_desync(_client(t), tool_name="read_file")
    name_probe, name_body = t.probes[1], t.bodies[1]
    assert name_probe[METHOD_HEADER] == "tools/call"
    assert name_probe[NAME_HEADER] != name_body["params"]["name"]


def test_the_absent_header_probe_clears_the_header_rather_than_faking_one():
    t = _HeaderTransport("accept")
    probe_header_desync(_client(t), tool_name="read_file")
    assert t.probes[-1][METHOD_HEADER] == ""


def test_probes_are_read_only():
    """Every body names an enumeration or a read - never a mutating call."""
    t = _HeaderTransport("accept")
    probe_header_desync(_client(t), tool_name="read_file", resource_uri="file://lab/policy")
    assert {b["method"] for b in t.bodies} <= {"tools/call", "resources/read", "tools/list"}
    for body in t.bodies:
        assert body.get("params", {}).get("arguments", {}) == {}


def test_a_server_with_no_tools_still_runs_the_header_probe():
    """The absent-header case needs no inventory, so it is never skipped."""
    t = _HeaderTransport("accept")
    findings = probe_header_desync(_client(t), tool_name="", resource_uri="")
    assert [f.probe for f in findings] == ["absent_method_header"]


def test_stdio_is_skipped_rather_than_reported_as_clean():
    """Headers do not exist on STDIO; an empty result must not read as a pass."""
    findings = probe_header_desync(_client(_StdioLikeTransport()), tool_name="read_file")
    assert findings == []
