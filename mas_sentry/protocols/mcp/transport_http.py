# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP+SSE and streamable-HTTP transports.

Streamable HTTP carries two pieces of per-connection state that live at the
transport layer rather than inside the JSON-RPC envelope, and a client that
drops either one is answered but not served.

The first is the session. A server MAY mint an `Mcp-Session-Id` on the response
to `initialize`; once it does, every later request MUST carry it back. A server
that issued one and receives a request without it answers HTTP 400 with
`-32600`, so the scanner reaches the endpoint, gets a well-formed refusal for
each enumeration call, and - because the enumeration helpers degrade an error to
an empty list - reports a fully populated server as having no tools, no prompts
and no resources. The reference SDK rig in lab/mcp caught exactly that: a real
server fingerprinted as zero tools while every downstream audit ran over nothing.

The second is the negotiated protocol revision. `initialize` proposes a version
and the server answers with the one it chose; from then on the client sends it
back in the `MCP-Protocol-Version` header. Omitting it does not always fail
loudly - the spec tells a server to assume 2025-03-26 when the header is absent,
so a silent downgrade is the likelier outcome, and the scanner then reasons
about a generation the server is not actually speaking.

Both are captured from whatever the server returns rather than assumed, since a
stateless deployment mints no session at all and must not be handed one.

The 2026-07-28 revision removes both. A modern server carries the protocol
envelope in `params._meta` and routes on the `Mcp-Method` and `Mcp-Name`
headers, so those are emitted per request when a modern revision is in force.
The headers are not decoration: a server MUST reject a request whose headers
disagree with its body, and getting them wrong turns every call into -32020.

A rejection arrives as HTTP 400 with a JSON-RPC error in the body, and that body
is the only place the reason is stated - -32022 names the revisions the server
does support, which is what a version-aware client falls back on. Reporting the
HTTP status alone would discard it.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Any

import httpx

from .jsonrpc import JsonRpcRequest, JsonRpcResponse

SESSION_HEADER = "Mcp-Session-Id"
PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
METHOD_HEADER = "Mcp-Method"
_PARSE_ERROR = -32700
NAME_HEADER = "Mcp-Name"
_INITIALIZE_METHOD = "initialize"

# Methods whose body carries a name the routing header must mirror. The key
# differs per method: resources/read routes on `uri`, not `name` - a detail that
# only shows up in the reference SDK, and getting it wrong is a -32020 on every
# resource read.
NAME_BEARING_METHODS = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}


@dataclass(slots=True)
class HttpConfig:
    url: str
    headers: dict[str, str] | None = None
    timeout: float = 15.0
    verify_tls: bool = True


def routing_headers(req: JsonRpcRequest) -> dict[str, str]:
    """Mcp-Method / Mcp-Name for a request, mirroring what the body says.

    A gateway routes and authorizes on these without parsing the body, which is
    the whole point of them - and also why a server must reject a request whose
    header and body disagree.
    """
    headers = {METHOD_HEADER: req.method}
    name_key = NAME_BEARING_METHODS.get(req.method)
    if name_key and isinstance(req.params, dict):
        value = req.params.get(name_key)
        if isinstance(value, str) and value:
            headers[NAME_HEADER] = value
    return headers


def _error_response(req: JsonRpcRequest, r: httpx.Response) -> JsonRpcResponse:
    """Decode a 4xx/5xx body, preserving the JSON-RPC error the server sent.

    A rejection states its reason only in the body: -32022 carries the list of
    revisions the server supports, and a version-aware client cannot fall back
    without it. Replacing that with the HTTP status - which is what this used to
    do - discards the one piece of information the response was carrying.
    """
    decoded, _ = _decode_body(r, req.id)
    # A JSON-RPC error the server actually sent is worth more than the status.
    # A parse failure is not one of those: the decoder reports -32700 for any
    # body it could not read, including plain-text proxy pages, and passing that
    # on would invent a protocol error where there was only an HTTP one.
    error = decoded.error or {}
    if decoded.result is not None or (decoded.is_error and error.get("code") != _PARSE_ERROR):
        return decoded
    return JsonRpcResponse(id=req.id, error={"code": r.status_code, "message": r.reason_phrase})


def _decode_body(r: httpx.Response, req_id: Any = None) -> tuple[JsonRpcResponse, list[dict[str, Any]]]:
    """Decode a body the server may have framed as SSE, JSON, or neither.

    Returns the answer to `req_id` together with any inbound traffic that came
    down the same body. A stream is not obliged to carry one message.
    """
    if "text/event-stream" in r.headers.get("content-type", ""):
        return _select_answer(_parse_sse(r.text), req_id)
    # Trust nothing: a server may send SSE without the header, or junk.
    try:
        return _select_answer([JsonRpcResponse.from_dict(r.json())], req_id)
    except (ValueError, TypeError):
        return _select_answer(_parse_sse(r.text), req_id)


def _parse_sse(text: str) -> list[JsonRpcResponse]:
    """Decode every `data:` frame in an SSE body; fall back to the raw text.

    Reading only the first frame was the HTTP half of the STDIO defect: a server
    that streams a notification ahead of the response hands back the
    notification, and the answer is silently dropped.
    """
    messages = [JsonRpcResponse.decode(line[5:].strip()) for line in text.splitlines() if line.startswith("data:")]
    return messages or [JsonRpcResponse.decode(text)]


def _select_answer(messages: list[JsonRpcResponse], req_id: Any) -> tuple[JsonRpcResponse, list[dict[str, Any]]]:
    """Split a decoded stream into our answer and everything else.

    A message carrying `method` is inbound - a notification, or a request the
    server is making of us - and is never an answer. Among the rest, the one
    bearing our id wins; with no id to match on, the first response does.
    """
    inbound: list[dict[str, Any]] = []
    answer: JsonRpcResponse | None = None
    for message in messages:
        if "method" in message.raw:
            inbound.append(message.raw)
            continue
        if answer is None and (req_id is None or message.id == req_id or message.id is None):
            answer = message
    if answer is None:
        answer = JsonRpcResponse(
            id=req_id,
            error={"message": f"server streamed {len(inbound)} message(s) but none answered the request"},
        )
    return answer, inbound


class HttpSseTransport:
    """Legacy SSE: POST request, response streamed back as `event: message`."""

    def __init__(self, config: HttpConfig) -> None:
        self.config = config
        self._client: httpx.Client | None = None
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        # Server-initiated traffic seen on the response stream. Kept for the
        # same reason STDIO keeps it: a mid-session tools/list_changed exists
        # nowhere else.
        self.notifications: list[dict[str, Any]] = []
        # Set by the client once it knows the target speaks a stateless
        # revision. Emitting routing headers at a legacy server is harmless but
        # pointless, and emitting them without the matching _meta envelope is a
        # guaranteed -32020, so the client owns the switch.
        self.emit_routing_headers = False

    def _request_headers(self, accept: str, req: JsonRpcRequest | None = None) -> dict[str, str]:
        """Per-request headers, carrying whatever protocol state the server set."""
        headers = {"content-type": "application/json", "accept": accept}
        if self.session_id:
            headers[SESSION_HEADER] = self.session_id
        if self.protocol_version:
            headers[PROTOCOL_VERSION_HEADER] = self.protocol_version
        if req is not None and self.emit_routing_headers:
            headers.update(routing_headers(req))
        return headers

    def _capture_protocol_state(
        self,
        req: JsonRpcRequest,
        response_headers: httpx.Headers,
        resp: JsonRpcResponse,
    ) -> None:
        """Adopt the session and the negotiated revision the server just named.

        The session header is read from every response, not only the one to
        `initialize`, because a server is free to mint it later; the version is
        read only from the `initialize` result, which is the one place the
        negotiation outcome is stated.
        """
        session_id = response_headers.get(SESSION_HEADER)
        if session_id:
            self.session_id = session_id
        if req.method != _INITIALIZE_METHOD or not isinstance(resp.result, dict):
            return
        version = resp.result.get("protocolVersion")
        if isinstance(version, str) and version:
            self.protocol_version = version

    def open(self) -> None:
        self._client = httpx.Client(
            headers=self.config.headers or {},
            timeout=self.config.timeout,
            verify=self.config.verify_tls,
        )

    def close(self) -> None:
        self._terminate_session()
        if self._client:
            self._client.close()
        self._client = None
        self.session_id = None
        self.protocol_version = None

    def _terminate_session(self) -> None:
        """Release a server-side session on the way out.

        A scanner opens many short-lived sessions against one target; leaving
        them to expire is a resource-exhaustion side effect we should not
        inflict. A server may refuse the DELETE outright, which is spec-legal
        and not our problem, so every failure here is swallowed.
        """
        if not self._client or not self.session_id:
            return
        with suppress(httpx.HTTPError):
            self._client.request(
                "DELETE",
                self.config.url,
                headers={SESSION_HEADER: self.session_id},
            )

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if not self._client:
            raise RuntimeError("Transport not open")
        body = req.encode()
        r = self._client.post(
            self.config.url,
            content=body,
            headers=self._request_headers("text/event-stream", req),
        )
        if r.status_code >= 400:
            return _error_response(req, r)
        resp, inbound = _decode_body(r, req.id)
        self.notifications.extend(inbound)
        self._capture_protocol_state(req, r.headers, resp)
        return resp

    supports_headers = True

    def send_with_extra_headers(self, req: JsonRpcRequest, overrides: dict[str, str]) -> JsonRpcResponse:
        """Send a request with routing headers set by the caller, not derived from the body.

        Exists for one audit: proving whether a server enforces agreement between
        its routing headers and the body requires sending a request where they
        disagree, which every other path in this module is built to prevent. An
        empty override value drops the header entirely, so the absent-header case
        is expressible too.
        """
        if not self._client:
            raise RuntimeError("Transport not open")
        headers = self._request_headers("application/json, text/event-stream", req)
        for key, value in overrides.items():
            if value:
                headers[key] = value
            else:
                headers.pop(key, None)
        r = self._client.post(self.config.url, json=req.to_dict(), headers=headers)
        if r.status_code >= 400:
            return _error_response(req, r)
        resp, inbound = _decode_body(r, req.id)
        self.notifications.extend(inbound)
        return resp


class StreamableHttpTransport(HttpSseTransport):
    """Modern transport: single bidi POST/JSON, server may answer JSON or SSE."""

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if not self._client:
            raise RuntimeError("Transport not open")
        r = self._client.post(
            self.config.url,
            json=req.to_dict(),
            headers=self._request_headers("application/json, text/event-stream", req),
        )
        if r.status_code >= 400:
            return _error_response(req, r)
        resp, inbound = _decode_body(r, req.id)
        self.notifications.extend(inbound)
        self._capture_protocol_state(req, r.headers, resp)
        return resp


@contextmanager
def open_http(config: HttpConfig, streamable: bool = True) -> Iterator[HttpSseTransport]:
    t: HttpSseTransport = StreamableHttpTransport(config) if streamable else HttpSseTransport(config)
    t.open()
    try:
        yield t
    finally:
        t.close()
