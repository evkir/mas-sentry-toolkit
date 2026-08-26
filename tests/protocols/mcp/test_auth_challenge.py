# SPDX-License-Identifier: AGPL-3.0-or-later
"""The pointer a 401 carries is the entry to the whole authorization chain."""

from typing import Any

import httpx

from mas_sentry.protocols.mcp.auth import parse_challenge
from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse
from mas_sentry.protocols.mcp.runtime import _run_all_checks
from mas_sentry.protocols.mcp.transport_http import HttpConfig, StreamableHttpTransport

_CHALLENGE = (
    'Bearer error="invalid_token", error_description="Authentication required", '
    'resource_metadata="https://target.test/.well-known/oauth-protected-resource/mcp"'
)


def test_a_challenge_is_read_into_its_parameters() -> None:
    challenge = parse_challenge(401, _CHALLENGE)
    assert challenge is not None
    assert challenge.scheme == "Bearer"
    assert challenge.params["error"] == "invalid_token"
    assert challenge.resource_metadata.endswith("/oauth-protected-resource/mcp")


def test_a_scheme_with_no_parameters_still_parses() -> None:
    """A bare challenge says the boundary exists even when it points nowhere."""
    challenge = parse_challenge(401, "Bearer")
    assert challenge is not None
    assert challenge.scheme == "Bearer"
    assert challenge.resource_metadata == ""
    assert "no resource_metadata parameter" in challenge.detail


def test_no_header_is_no_challenge() -> None:
    assert parse_challenge(401, "") is None
    assert parse_challenge(401, "   ") is None


def test_an_oversized_header_is_bounded() -> None:
    """The header is written by the target."""
    challenge = parse_challenge(401, "Bearer " + 'x="y", ' * 5000)
    assert challenge is not None
    assert len(challenge.raw) <= 2000


def test_the_transport_keeps_a_401_challenge() -> None:
    transport = StreamableHttpTransport(HttpConfig(url="https://target.test/mcp"))
    transport._capture_challenge(httpx.Response(401, headers={"WWW-Authenticate": _CHALLENGE}))
    assert transport.auth_challenge is not None
    assert transport.auth_challenge.status == 401


def test_the_transport_ignores_a_challenge_on_other_statuses() -> None:
    """A header read off a 500 would record a challenge no client would act on."""
    transport = StreamableHttpTransport(HttpConfig(url="https://target.test/mcp"))
    transport._capture_challenge(httpx.Response(500, headers={"WWW-Authenticate": _CHALLENGE}))
    assert transport.auth_challenge is None


class _RefusingTransport:
    def __init__(self) -> None:
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False
        self.auth_challenge = parse_challenge(401, _CHALLENGE)

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        if body["method"] == DISCOVER_METHOD:
            return JsonRpcResponse(
                id=body.get("id"),
                result={
                    "capabilities": {"tools": {}},
                    "cacheScope": "private",
                    "resultType": "complete",
                    "ttlMs": 0,
                    "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
                },
            )
        return JsonRpcResponse(id=body.get("id"), error={"code": 401, "message": "Unauthorized"})

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def test_the_scan_reports_the_boundary_it_did_not_cross() -> None:
    rows = _run_all_checks(McpClient(_RefusingTransport()), transport="http", checks="all")
    auth = next(r for r in rows if r["check"] == "auth_required")
    assert auth["severity"] == "MEDIUM"
    assert "oauth-protected-resource" in auth["detail"]
    assert "nothing behind the authorization boundary" in auth["detail"]
