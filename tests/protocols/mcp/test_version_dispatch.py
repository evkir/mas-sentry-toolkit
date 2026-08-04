# SPDX-License-Identifier: AGPL-3.0-or-later
"""Route negotiation: stateless 2026-07-28 first, handshake as the fallback."""

from typing import Any

import pytest

from mas_sentry.protocols.mcp.client import (
    DISCOVER_METHOD,
    LEGACY_PROTOCOL_VERSION,
    META_CLIENT_CAPABILITIES,
    META_PROTOCOL_VERSION,
    META_SERVER_INFO,
    MODERN_PROTOCOL_VERSION,
    McpClient,
)
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse


class _ScriptedTransport:
    """Answers by method name; records every request that reached the wire."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.sent: list[dict[str, Any]] = []
        self.emit_routing_headers = False
        self.protocol_version: str | None = None

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        self.sent.append(body)
        answer = self.answers.get(body["method"], {"error": {"code": -32601, "message": "Method not found"}})
        if callable(answer):
            answer = answer(body)
        if "error" in answer:
            return JsonRpcResponse(id=body.get("id"), error=answer["error"])
        return JsonRpcResponse(id=body.get("id"), result=answer.get("result", {}))

    def methods(self) -> list[str]:
        return [r["method"] for r in self.sent]


def _discover_result(name: str = "rig", version: str = "1.0") -> dict[str, Any]:
    return {
        "result": {
            "capabilities": {"tools": {}},
            "instructions": "lab",
            "cacheScope": "private",
            "resultType": "complete",
            "supportedVersions": [MODERN_PROTOCOL_VERSION],
            "ttlMs": 0,
            "_meta": {META_SERVER_INFO: {"name": name, "version": version}},
        }
    }


def _initialize_result() -> dict[str, Any]:
    return {
        "result": {
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "serverInfo": {"name": "legacy-rig", "version": "0.9"},
        }
    }


def test_modern_server_is_reached_without_a_handshake():
    t = _ScriptedTransport({DISCOVER_METHOD: _discover_result()})
    client = McpClient(t)
    info = client.connect()
    assert client.is_modern
    assert info.name == "rig"
    assert "initialize" not in t.methods()


def test_server_identity_is_read_from_the_result_meta():
    """discover nests serverInfo in result._meta; the handshake put it top level.

    Reading the handshake location against a modern server yields a nameless
    server that matches no known implementation fingerprint.
    """
    t = _ScriptedTransport({DISCOVER_METHOD: _discover_result(name="vuln-mcp-ref", version="0.1.0")})
    info = McpClient(t).connect()
    assert (info.name, info.version) == ("vuln-mcp-ref", "0.1.0")


def test_every_modern_request_carries_the_envelope():
    t = _ScriptedTransport(
        {
            DISCOVER_METHOD: _discover_result(),
            "tools/list": {"result": {"tools": [{"name": "echo"}]}},
        }
    )
    client = McpClient(t)
    client.connect()
    client.list_tools()
    listing = next(r for r in t.sent if r["method"] == "tools/list")
    meta = listing["params"]["_meta"]
    assert meta[META_PROTOCOL_VERSION] == MODERN_PROTOCOL_VERSION
    assert META_CLIENT_CAPABILITIES in meta


def test_unknown_discover_method_falls_back_to_the_handshake():
    """A 2025-line server does not know server/discover. -32601 is that answer."""
    t = _ScriptedTransport({"initialize": _initialize_result()})
    client = McpClient(t)
    info = client.connect()
    assert not client.is_modern
    assert info.name == "legacy-rig"
    assert t.methods()[0] == DISCOVER_METHOD
    assert "initialize" in t.methods()


def test_legacy_requests_carry_no_envelope():
    t = _ScriptedTransport({"initialize": _initialize_result(), "tools/list": {"result": {"tools": []}}})
    client = McpClient(t)
    client.connect()
    client.list_tools()
    listing = next(r for r in t.sent if r["method"] == "tools/list")
    assert "_meta" not in (listing.get("params") or {})


def test_unsupported_version_retries_on_a_revision_the_server_named():
    """-32022 carries the supported list; that is the whole point of the code."""
    older = "2025-11-25"
    calls = {"n": 0}

    def discover(_body: dict[str, Any]) -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            return {
                "error": {
                    "code": -32022,
                    "message": "Unsupported protocol version",
                    "data": {"supported": [older], "requested": MODERN_PROTOCOL_VERSION},
                }
            }
        return _discover_result(name="older-rig")

    t = _ScriptedTransport({DISCOVER_METHOD: discover})
    client = McpClient(t)
    info = client.connect()
    assert client.is_modern
    assert client.protocol_version == older
    assert info.name == "older-rig"
    assert calls["n"] == 2


def test_a_server_rejecting_the_version_it_offers_does_not_loop():
    """Guard against a target that answers -32022 listing the version we sent."""
    t = _ScriptedTransport(
        {
            DISCOVER_METHOD: {
                "error": {
                    "code": -32022,
                    "message": "Unsupported protocol version",
                    "data": {"supported": [MODERN_PROTOCOL_VERSION], "requested": MODERN_PROTOCOL_VERSION},
                }
            },
            "initialize": _initialize_result(),
        }
    )
    client = McpClient(t)
    client.connect()
    assert t.methods().count(DISCOVER_METHOD) == 1
    assert not client.is_modern


def test_an_unrelated_error_does_not_masquerade_as_a_downgrade():
    """A server that is merely broken must not be reported as a 2025 server.

    The handshake still runs, but nothing about the modern route was learned -
    it failed for a reason that has no protocol meaning.
    """
    t = _ScriptedTransport(
        {
            DISCOVER_METHOD: {"error": {"code": -32603, "message": "Internal error"}},
            "initialize": _initialize_result(),
        }
    )
    client = McpClient(t)
    client.connect()
    assert not client.is_modern


def test_a_dead_server_surfaces_the_handshake_failure():
    t = _ScriptedTransport({})
    with pytest.raises(RuntimeError, match="initialize failed"):
        McpClient(t).connect()


def test_discover_metadata_is_kept_for_the_auditors():
    """cacheScope and ttlMs have no handshake equivalent and are worth auditing."""
    t = _ScriptedTransport({DISCOVER_METHOD: _discover_result()})
    client = McpClient(t)
    client.connect()
    assert client.discover_result["cacheScope"] == "private"
    assert client.discover_result["supportedVersions"] == [MODERN_PROTOCOL_VERSION]
