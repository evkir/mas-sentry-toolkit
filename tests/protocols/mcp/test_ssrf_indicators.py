# SPDX-License-Identifier: AGPL-3.0-or-later
"""An SSRF confirmation has to come from the target, not from our own payload."""

from typing import Any

from mas_sentry.protocols.mcp.audit.ssrf import _INDICATORS, _SENSITIVE_URLS, _ssrf_indicator, probe_ssrf
from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse
from mas_sentry.protocols.mcp.runtime import _run_all_checks

GCP_URL = "http://metadata.google.internal/computeMetadata/v1/"

# Observed from the lab rig that produced the false positive this module pins:
# a tool that answers by repeating the URL it was handed.
ECHO_BODY = f"contents of {GCP_URL}"

# Observed shape of a GCP metadata refusal to a request without the header.
GCP_REFUSAL = 'GKE Metadata Server encountered an error: Missing required header "Metadata-Flavor": "Google"'

_DISCOVER = {
    "result": {
        "capabilities": {"tools": {}},
        "resultType": "complete",
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


class _Transport:
    """Answers every tools/call according to `mode`, which decides the body."""

    def __init__(self, answers: dict[str, Any], mode: str) -> None:
        self.answers = answers
        self.mode = mode
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        method = body["method"]
        if method == "tools/call":
            url = body.get("params", {}).get("arguments", {}).get("url", "")
            if self.mode == "echo":
                text = f"contents of {url}"
            elif self.mode == "metadata" and "metadata.google" in url:
                text = GCP_REFUSAL
            else:
                text = "0 bytes fetched"
            return JsonRpcResponse(id=body.get("id"), result={"content": [{"type": "text", "text": text}]})
        answer = self.answers.get(method, {"error": {"code": -32601, "message": "Method not found"}})
        if "error" in answer:
            return JsonRpcResponse(id=body.get("id"), error=answer["error"])
        return JsonRpcResponse(id=body.get("id"), result=answer.get("result", {}))

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _client(mode: str) -> McpClient:
    return McpClient(_Transport({DISCOVER_METHOD: _DISCOVER, "tools/list": _TOOLS}, mode=mode))


def test_no_indicator_token_can_be_read_off_our_own_payload() -> None:
    """The invariant the GCP row broke, checked over the whole table.

    A token that appears in a payload confirms on any tool that echoes its
    argument, which is a legal thing for a tool to do and therefore a false
    positive on the highest severity this scanner emits.
    """
    for url in _SENSITIVE_URLS:
        lowered = url.lower()
        for marker, tokens in _INDICATORS:
            for token in tokens:
                assert token not in lowered, f"{token!r} is readable from the payload {url!r} ({marker})"


def test_an_echoed_url_does_not_confirm() -> None:
    assert _ssrf_indicator(GCP_URL, ECHO_BODY) is False


def test_a_refusal_from_the_metadata_server_does_confirm() -> None:
    """The 403 is proof the tool reached the service, which is the finding."""
    assert _ssrf_indicator(GCP_URL, GCP_REFUSAL) is True


def test_an_echoing_tool_produces_no_critical_row() -> None:
    rows = _run_all_checks(_client("echo"), transport="http", checks="all")
    assert [r for r in rows if r["check"] == "ssrf"] == []


def test_a_tool_that_reaches_the_metadata_service_still_produces_one() -> None:
    """Pinned in both directions: the fix must not have turned the check off."""
    confirmed = [f for f in probe_ssrf(_client("metadata")) if f.status == "OK"]
    assert len(confirmed) == 1
    assert confirmed[0].url == GCP_URL


def test_a_confirmed_hit_carries_what_came_back_into_the_report() -> None:
    """The evidence has to reach the row, or the severity rests on nothing."""
    rows = _run_all_checks(_client("metadata"), transport="http", checks="all")
    hits = [r for r in rows if r["check"] == "ssrf"]
    assert len(hits) == 1
    assert hits[0]["severity"] == "CRITICAL"
    assert "fetch_url" in hits[0]["detail"]
    assert "Metadata-Flavor" in hits[0]["detail"]
