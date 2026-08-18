# SPDX-License-Identifier: AGPL-3.0-or-later
"""The consent surface is audited for what a person could not have checked."""

from typing import Any

from mas_sentry.protocols.mcp.audit.elicitation import audit_elicitations
from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, ElicitationRequest, McpClient
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


class _Config:
    def __init__(self, url: str) -> None:
        self.url = url


class _Transport:
    def __init__(self, answers: dict[str, Any], url: str = "") -> None:
        self.answers = answers
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False
        if url:
            self.config = _Config(url)

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        answer = self.answers.get(body["method"], {"error": {"code": -32601, "message": "Method not found"}})
        if "error" in answer:
            return JsonRpcResponse(id=body.get("id"), error=answer["error"])
        return JsonRpcResponse(id=body.get("id"), result=answer.get("result", {}))

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _client_with(*requests: ElicitationRequest, url: str = "") -> McpClient:
    client = McpClient(_Transport({DISCOVER_METHOD: _DISCOVER}, url=url))
    client.elicitations.extend(requests)
    return client


def _url_request(url: str) -> ElicitationRequest:
    return ElicitationRequest(method="tools/call", mode="url", message="authorize", url=url, fields=())


def _form_request(*fields: tuple[str, str]) -> ElicitationRequest:
    return ElicitationRequest(method="tools/call", mode="form", message="details", url="", fields=fields)


def test_an_https_consent_url_on_the_scanned_origin_is_not_a_finding() -> None:
    """The detector has to be silent on the honest case or it says nothing at all."""
    client = _client_with(_url_request("https://target.test/oauth/authorize"), url="https://target.test/mcp")
    assert audit_elicitations(client) == []


def test_a_form_collecting_ordinary_fields_is_not_a_finding() -> None:
    client = _client_with(_form_request(("workspace", "Which workspace"), ("project", "Project name")))
    assert audit_elicitations(client) == []


def test_a_cleartext_consent_url_is_high() -> None:
    client = _client_with(_url_request("http://consent.test/authorize"))
    finding = audit_elicitations(client)[0]
    assert finding.check == "elicitation_url"
    assert finding.severity == "HIGH"
    assert "in the clear" in finding.detail


def test_loopback_over_http_is_left_alone() -> None:
    """A locally spawned server authorizing on loopback is the normal case."""
    for url in ("http://127.0.0.1:8931/authorize", "http://localhost:8931/authorize"):
        assert audit_elicitations(_client_with(_url_request(url))) == []


def test_credentials_ahead_of_the_host_are_high() -> None:
    client = _client_with(_url_request("https://accounts.target.test@evil.test/authorize"))
    finding = audit_elicitations(client)[0]
    assert finding.severity == "HIGH"
    assert "hides where it goes" in finding.detail


def test_a_bare_address_is_medium() -> None:
    client = _client_with(_url_request("https://203.0.113.9/authorize"))
    finding = audit_elicitations(client)[0]
    assert finding.severity == "MEDIUM"
    assert "bare address" in finding.detail


def test_leaving_the_origin_is_reported_but_not_asserted_as_a_weakness() -> None:
    """An identity provider is off-origin by definition; a severity here would be noise."""
    client = _client_with(_url_request("https://idp.example/authorize"), url="https://target.test/mcp")
    finding = audit_elicitations(client)[0]
    assert finding.severity == "INFO"
    assert "leaves the scanned origin" in finding.detail


def test_no_origin_is_known_on_stdio_so_no_origin_claim_is_made() -> None:
    assert audit_elicitations(_client_with(_url_request("https://idp.example/authorize"))) == []


def test_a_secret_field_name_is_high_and_a_secret_description_is_medium() -> None:
    """A name is chosen; a description is prose, and prose mentions passwords innocently."""
    named = _client_with(_form_request(("api_key", "for the integration")))
    assert audit_elicitations(named)[0].severity == "HIGH"
    assert audit_elicitations(named)[0].check == "elicitation_secret_field"
    described = _client_with(_form_request(("value", "paste your recovery phrase here")))
    assert audit_elicitations(described)[0].severity == "MEDIUM"


def test_both_lenses_can_fire_on_one_request() -> None:
    request = ElicitationRequest(
        method="tools/call",
        mode="form",
        message="sign in",
        url="http://evil.test/login",
        fields=(("password", ""),),
    )
    checks = {f.check for f in audit_elicitations(_client_with(request))}
    assert checks == {"elicitation_url", "elicitation_secret_field"}


def test_runtime_carries_the_finding_into_the_report() -> None:
    client = _client_with(_url_request("http://evil.test/authorize"))
    rows = _run_all_checks(client, transport="http", checks="all")
    urls = [r for r in rows if r["check"] == "elicitation_url"]
    assert len(urls) == 1
    assert urls[0]["severity"] == "HIGH"
