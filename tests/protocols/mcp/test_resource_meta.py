# SPDX-License-Identifier: AGPL-3.0-or-later
"""A ui:// resource says what its iframe may reach; the listing has to keep it."""

from typing import Any

from mas_sentry.protocols.mcp.client import APP_MIME_TYPE, DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse

_DISCOVER = {
    "result": {
        "capabilities": {"resources": {}},
        "cacheScope": "private",
        "resultType": "complete",
        "ttlMs": 0,
        "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
    }
}

_UI_RESOURCE = {
    "uri": "ui://clock/app.html",
    "name": "clock",
    "mimeType": APP_MIME_TYPE,
    "_meta": {
        "ui": {
            "csp": {"connectDomains": ["https://api.clock.test"], "resourceDomains": ["https://cdn.clock.test"]},
            "permissions": {"clipboardWrite": {}},
            "domain": "clock.test",
        }
    },
}


class _Transport:
    def __init__(self, resources: list[dict[str, Any]]) -> None:
        self.resources = resources
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        if body["method"] == DISCOVER_METHOD:
            return JsonRpcResponse(id=body.get("id"), result=_DISCOVER["result"])
        if body["method"] == "resources/list":
            return JsonRpcResponse(id=body.get("id"), result={"resources": self.resources})
        return JsonRpcResponse(id=body.get("id"), error={"code": -32601, "message": "Method not found"})

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _listed(resources: list[dict[str, Any]]) -> Any:
    client = McpClient(_Transport(resources))
    client.connect()
    return client.list_resources()


def test_the_ui_settings_survive_the_listing() -> None:
    """csp and permissions are the whole audit surface of an app resource."""
    resource = _listed([_UI_RESOURCE])[0]
    ui = resource.meta["ui"]
    assert ui["csp"]["connectDomains"] == ["https://api.clock.test"]
    assert "clipboardWrite" in ui["permissions"]
    assert resource.mime_type == APP_MIME_TYPE


def test_a_resource_without_meta_reads_as_an_empty_mapping() -> None:
    """Callers index into this; None would make every reader defend against it."""
    resource = _listed([{"uri": "file:///notes", "name": "notes"}])[0]
    assert resource.meta == {}


def test_a_malformed_meta_is_not_carried_through() -> None:
    """The listing is the target's to write, and a string is not a mapping."""
    resource = _listed([{"uri": "file:///notes", "_meta": "not-a-mapping"}])[0]
    assert resource.meta == {}
