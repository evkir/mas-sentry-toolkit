# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detect a server that does not enforce agreement between routing headers and body.

The 2026-07-28 revision made `Mcp-Method` mandatory on every Streamable HTTP
request and `Mcp-Name` mandatory on the three methods that name a target, so a
gateway can route and authorize an MCP call without parsing the JSON-RPC body.
That is the point of the headers, and it is also the whole risk: two parties now
read the same request, and only one of them reads the body.

The spec therefore requires the server to reject any request whose headers
disagree with its body. A server that does not is not merely non-conforming - it
hands an attacker a request that a policy layer authorizes as one operation and
the server executes as another. `Mcp-Method: tools/list` sails past a gateway
that only permits read-only enumeration while the body says `tools/call`. Or the
method matches and only `Mcp-Name` differs: the gateway sees the tool an
operator approved, the server runs a different one.

Four probes, each sending a deliberately inconsistent request. The right answer
to all four is a rejection - the reference SDK answers -32020 - so a success is
the finding. The probes are read-only by construction: the body always names a
listing or a read with empty arguments, because the point is to learn whether
the check exists, not to exercise what slips past it.

Applies to HTTP transports only. STDIO frames requests without headers, so the
desync this looks for cannot be expressed there, and reporting its absence as a
clean result would be a false negative dressed as a pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..client import HEADER_MISMATCH, McpClient
from ..jsonrpc import JsonRpcCodec, JsonRpcResponse
from ..transport_http import METHOD_HEADER, NAME_HEADER

# Any of these means the server looked and refused. -32020 is what the reference
# SDK returns; the others are servers that reject on a coarser rung, which is
# still a rejection and still safe.
_REJECTION_CODES = {
    HEADER_MISMATCH,  # -32020, the specific "headers disagree" answer
    -32600,  # Invalid Request
    -32602,  # Invalid params
    400,
    403,
    422,
}


@dataclass(frozen=True, slots=True)
class DesyncFinding:
    probe: str
    detail: str
    status: str  # "accepted" | "rejected" | "inconclusive"
    body_method: str
    header_method: str
    body_name: str = ""
    header_name: str = ""


def _classify(resp: JsonRpcResponse) -> str:
    """Rejected, accepted, or an answer that settles nothing."""
    if not resp.is_error:
        return "accepted"
    error = resp.error or {}
    code = error.get("code")
    if isinstance(code, int) and code in _REJECTION_CODES:
        return "rejected"
    # A server answering -32601 never reached the header check: the method it
    # was asked for does not exist, so the request tells us nothing about
    # whether headers are validated. Crediting that as a rejection would be
    # exactly the false pass this audit exists to prevent.
    return "inconclusive"


def _send_with_headers(
    client: McpClient, method: str, params: dict[str, Any], headers: dict[str, str]
) -> JsonRpcResponse:
    """Send one request with hand-set routing headers.

    This deliberately does not go through client.send(), which exists to keep
    headers and body consistent. Provoking the inconsistency is the measurement.
    """
    body = client.envelope(params) if client.is_modern else dict(params)
    req = JsonRpcCodec.request(method, body, req_id=client.next_id())
    return client.transport.send_with_extra_headers(req, headers)


def probe_header_desync(client: McpClient, tool_name: str = "", resource_uri: str = "") -> list[DesyncFinding]:
    """Send four inconsistent requests and report what the server let through.

    `tool_name` and `resource_uri` come from the inventory the scan already
    walked; probes needing a target the server does not have are skipped rather
    than sent against an invented name, whose "method not found" would be
    inconclusive anyway.
    """
    if not getattr(client.transport, "supports_headers", False):
        return []

    out: list[DesyncFinding] = []

    # 1. Header claims a listing, body calls a tool. The gateway-bypass case.
    if tool_name:
        resp = _send_with_headers(
            client,
            "tools/call",
            {"name": tool_name, "arguments": {}},
            {METHOD_HEADER: "tools/list", NAME_HEADER: tool_name},
        )
        out.append(
            DesyncFinding(
                probe="method_mismatch",
                detail=(
                    f"Mcp-Method: tools/list carried a tools/call body for {tool_name!r}. "
                    "A gateway authorizing on the header permits enumeration; the server runs the call."
                ),
                status=_classify(resp),
                body_method="tools/call",
                header_method="tools/list",
                body_name=tool_name,
                header_name=tool_name,
            )
        )

    # 2. Method agrees, the named target does not.
    if tool_name:
        decoy = f"{tool_name}-approved"
        resp = _send_with_headers(
            client,
            "tools/call",
            {"name": tool_name, "arguments": {}},
            {METHOD_HEADER: "tools/call", NAME_HEADER: decoy},
        )
        out.append(
            DesyncFinding(
                probe="name_mismatch",
                detail=(
                    f"Mcp-Name: {decoy!r} carried a body calling {tool_name!r}. "
                    "A gateway allow-listing tools by name sees one tool and the server runs another."
                ),
                status=_classify(resp),
                body_method="tools/call",
                header_method="tools/call",
                body_name=tool_name,
                header_name=decoy,
            )
        )

    # 3. resources/read routes on uri, not name - a distinct code path.
    if resource_uri:
        resp = _send_with_headers(
            client,
            "resources/read",
            {"uri": resource_uri},
            {METHOD_HEADER: "resources/read", NAME_HEADER: "file://approved/placeholder"},
        )
        out.append(
            DesyncFinding(
                probe="uri_mismatch",
                detail=(
                    f"Mcp-Name named a different resource than the body read ({resource_uri!r}). "
                    "resources/read routes on uri, so this is the resource side of the same bypass."
                ),
                status=_classify(resp),
                body_method="resources/read",
                header_method="resources/read",
                body_name=resource_uri,
                header_name="file://approved/placeholder",
            )
        )

    # 4. No routing header at all. A server that requires them cannot be routed
    #    around by simply omitting them.
    resp = _send_with_headers(client, "tools/list", {}, {METHOD_HEADER: ""})
    out.append(
        DesyncFinding(
            probe="absent_method_header",
            detail=(
                "A request with no Mcp-Method was served. A gateway that routes on the header "
                "has nothing to route on, and whatever it does by default becomes the policy."
            ),
            status=_classify(resp),
            body_method="tools/list",
            header_method="",
        )
    )
    return out
