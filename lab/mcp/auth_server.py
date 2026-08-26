# SPDX-License-Identifier: AGPL-3.0-or-later
"""An MCP resource server that answers 401 with a real RFC 9728 discovery chain.

Built on the reference SDK's own route builders rather than on hand-written
JSON, for the reason every rig in this directory exists: a fixture written by
the same person who wrote the parser agrees with the parser. `mcp.server.auth`
decides here what the metadata document looks like and where it is mounted, so
a divergence between MST and a conforming server surfaces as a failing test.

The MCP endpoint itself only refuses. Standing up a working authorization
server would test an OAuth library, not MST - what MST has to get right is the
refusal, the pointer it carries, and the two metadata documents behind it.

Environment:
    MAS_SENTRY_AUTH_PORT   port to bind (default 9810)
    MAS_SENTRY_AUTH_BREAK  omit one thing, to pin the audit in both directions:
                           `challenge` drops the WWW-Authenticate header,
                           `prm` unmounts the protected resource metadata,
                           `pkce` drops S256 from the authorization server.
"""

from __future__ import annotations

import os

import uvicorn
from mcp.server.auth.routes import build_resource_metadata_url, create_protected_resource_routes
from mcp.shared.auth import OAuthMetadata
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

PORT = int(os.environ.get("MAS_SENTRY_AUTH_PORT", "9810"))
BREAK = os.environ.get("MAS_SENTRY_AUTH_BREAK", "")
BASE = f"http://127.0.0.1:{PORT}"
RESOURCE = AnyHttpUrl(f"{BASE}/mcp")
ISSUER = AnyHttpUrl(BASE)


async def mcp_endpoint(request: object) -> Response:
    """Refuse the way the SDK's bearer middleware refuses."""
    headers = {}
    if BREAK != "challenge":
        headers["WWW-Authenticate"] = (
            'Bearer error="invalid_token", error_description="Authentication required", '
            f'resource_metadata="{build_resource_metadata_url(RESOURCE)}"'
        )
    return Response(
        content='{"error": "invalid_token", "error_description": "Authentication required"}',
        status_code=401,
        media_type="application/json",
        headers=headers,
    )


async def as_metadata(request: object) -> JSONResponse:
    meta = OAuthMetadata(
        issuer=ISSUER,
        authorization_endpoint=AnyHttpUrl(f"{BASE}/authorize"),
        token_endpoint=AnyHttpUrl(f"{BASE}/token"),
        registration_endpoint=AnyHttpUrl(f"{BASE}/register"),
        response_types_supported=["code"],
        code_challenge_methods_supported=[] if BREAK == "pkce" else ["S256"],
        authorization_response_iss_parameter_supported=True,
    )
    return JSONResponse(meta.model_dump(by_alias=True, mode="json", exclude_none=True))


def build_app() -> Starlette:
    routes = [
        Route("/mcp", endpoint=mcp_endpoint, methods=["GET", "POST"]),
        Route("/.well-known/oauth-authorization-server", endpoint=as_metadata, methods=["GET"]),
    ]
    if BREAK != "prm":
        routes.extend(create_protected_resource_routes(resource_url=RESOURCE, authorization_servers=[ISSUER]))
    return Starlette(routes=routes)


app = build_app()


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="error")
