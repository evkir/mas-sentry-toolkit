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
    def __init__(self, tools: list[dict[str, Any]], resources: list[dict[str, Any]]) -> None:
        self.tools = tools
        self.resources = resources
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


def _audit(tools: list[dict[str, Any]], resources: list[dict[str, Any]]) -> list[Any]:
    client = McpClient(_Transport(tools, resources))
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
