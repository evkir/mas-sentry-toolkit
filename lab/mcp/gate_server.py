# SPDX-License-Identifier: AGPL-3.0-or-later
"""An authorization boundary announced at the edge and not applied. DO NOT DEPLOY.

Source: CVE-2026-59822 (`litellm` < 1.84.0, CWE-287 and CWE-306, CVSS 4.0 8.8;
GHSA-7488-6r32-c95q), the first MCP defect added to CISA's Known Exploited
Vulnerabilities catalog. Read off the published packages rather than off a
write-up: `litellm` 1.83.9 and 1.84.0 from PyPI, file
`litellm/proxy/_experimental/mcp_server/auth/user_api_key_auth_mcp.py`.

The gate in 1.83.9 decides in four branches, and this rig reproduces all four
because which one answers is the whole question:

    1. `if ".well-known" in str(request.url)`        -> public, no auth
    2. `elif has_explicit_litellm_key`               -> validate for real
    3. `elif oauth2_headers`                         -> validate, and on 401/403
                                                        substitute an empty
                                                        UserAPIKeyAuth()
    4. `else`                                        -> validate an empty key

Branch 3 is the headline defect: an unauthenticated caller sends any
Authorization value, key validation fails, and the OAuth2 passthrough fallback
replaces the failure with an authenticated session. Nothing checks the value's
shape - `_get_oauth2_headers_from_headers` takes any header whose name starts
with `authorization`, so there is no Bearer prefix, no JWT form, no `sk-` to
guess. 1.84.0 gates the fallback on the target server being configured
`auth_type=oauth2`.

Branch 1 is the second defect in the same fix: the public-route test matched the
substring anywhere in the URL, so `?.well-known` appended to any MCP route made
it public. 1.84.0 matches `request.url.path.startswith("/.well-known/")`. Of the
three vectors its comment names - query string, hostname, deeper URL segment -
only the query form changes exactly one variable from the baseline request: a
hostname is not the scanner's to choose, and a deeper path segment changes the
route, so a 404 would read as a refusal that the gate never made.

The gate is an ASGI wrapper around the SDK's own `streamable_http_app()`, which
is where the real defect lives too: a proxy in front of MCP, deciding before any
MCP code runs. So what the wire carries past the gate is the reference SDK's
doing and not this file's.

Four modes, because a detector is only worth shipping if the fixed shape makes
it stay quiet (R-2.4). Each mode admits at most one defect, so a probe that
cannot tell them apart fails here rather than in the field:

    strict         the fix. Branch 1 matches the real path only, branch 3 does
                   not fall back. Every unauthenticated call is refused.
    bearer-any     branch 3 as 1.83.9 wrote it. Any Authorization value works.
    public-marker  branch 1 as 1.83.9 wrote it. `?.well-known` works.
    open           no boundary at all, which is a legitimate local server and
                   must not be reported as a bypass.

Environment:
    MAS_SENTRY_GATE_MODE    "strict" (default), "bearer-any", "public-marker",
                            "open"
    MAS_SENTRY_GATE_PORT    port to bind (default 9820)
    MAS_SENTRY_GATE_MARKER  a path the tool's body writes if it ever runs.
                            Nothing in a correct scan should create it: the
                            probe establishes whether a session is reachable,
                            which takes `initialize` and `tools/list` and never
                            a `tools/call` (R-7.6). This marker is what holds
                            the claim to the disk instead of to a comment.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import Response

PORT = int(os.environ.get("MAS_SENTRY_GATE_PORT", "9820"))

# RFC 6750 Section 3: the body of a 401 from a resource server is
# {"error": "invalid_token", ...} - a string where a JSON-RPC message would
# carry an object. Kept because that shape is what a scan has to survive.
REFUSAL_BODY = '{"error": "invalid_token", "error_description": "Authentication required"}'
CHALLENGE = {"WWW-Authenticate": 'Bearer error="invalid_token", error_description="Authentication required"'}

LITELLM_KEY_HEADER = "x-litellm-api-key"

app = MCPServer("gate-rig")


@app.tool()
def read_notes(key: str) -> str:
    """The inventory behind the boundary. One required string, so a call is cheap to build."""
    marker = os.environ.get("MAS_SENTRY_GATE_MARKER")
    if marker:
        Path(marker).write_text("BODY_EXECUTED", encoding="utf-8")
    return f"note:{key}"


inner = app.streamable_http_app()


def _mode() -> str:
    return os.environ.get("MAS_SENTRY_GATE_MODE", "strict")


def _admits(request: Request, mode: str) -> bool:
    """The 1.83.9 gate, branch for branch. Key validation always fails here.

    It always fails because the caller this rig exists to model holds no key.
    That is not a simplification of the CVE - it is the CVE: the fallback is
    reached precisely when validation says no.
    """
    if mode == "open":
        return True
    # Branch 1. The defect matches the substring anywhere in the URL; the fix
    # matches the path, which a query string cannot reach.
    marker_in_url = ".well-known" in str(request.url)
    path_is_well_known = request.url.path.startswith("/.well-known/")
    if path_is_well_known or (marker_in_url and mode == "public-marker"):
        return True
    # Branch 2. An explicit LiteLLM key is always validated for real, so it is
    # never the way in - present here because leaving it out would make the rig
    # agree with a probe that mistook branch 3 for branch 2.
    if request.headers.get(LITELLM_KEY_HEADER) is not None:
        return False
    # Branch 3 admits any header whose name starts with `authorization`,
    # whatever its value. Branch 4 and the refused tails of 2 and 3 all land on
    # the same answer, which is why this is one return rather than two.
    has_authorization = any(name.lower().startswith("authorization") for name in request.headers)
    return has_authorization and mode == "bearer-any"


async def gate(scope: dict[str, Any], receive: Any, send: Any) -> None:
    """Decide before any MCP code runs, which is where the real defect sits."""
    if scope["type"] != "http":
        await inner(scope, receive, send)
        return
    if _admits(Request(scope=scope), _mode()):
        await inner(scope, receive, send)
        return
    refusal = Response(
        content=REFUSAL_BODY,
        status_code=401,
        media_type="application/json",
        headers=CHALLENGE,
    )
    await refusal(scope, receive, send)


if __name__ == "__main__":
    uvicorn.run(gate, host="127.0.0.1", port=PORT, log_level="error")
