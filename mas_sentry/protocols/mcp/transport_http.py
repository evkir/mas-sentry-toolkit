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
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass

import httpx

from .jsonrpc import JsonRpcRequest, JsonRpcResponse

SESSION_HEADER = "Mcp-Session-Id"
PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
_INITIALIZE_METHOD = "initialize"


@dataclass(slots=True)
class HttpConfig:
    url: str
    headers: dict[str, str] | None = None
    timeout: float = 15.0
    verify_tls: bool = True


def _parse_sse(text: str) -> JsonRpcResponse:
    """Extract the first `data:` line from an SSE body; fall back to raw."""
    for line in text.splitlines():
        if line.startswith("data:"):
            return JsonRpcResponse.decode(line[5:].strip())
    return JsonRpcResponse.decode(text)


class HttpSseTransport:
    """Legacy SSE: POST request, response streamed back as `event: message`."""

    def __init__(self, config: HttpConfig) -> None:
        self.config = config
        self._client: httpx.Client | None = None
        self.session_id: str | None = None
        self.protocol_version: str | None = None

    def _request_headers(self, accept: str) -> dict[str, str]:
        """Per-request headers, carrying whatever protocol state the server set."""
        headers = {"content-type": "application/json", "accept": accept}
        if self.session_id:
            headers[SESSION_HEADER] = self.session_id
        if self.protocol_version:
            headers[PROTOCOL_VERSION_HEADER] = self.protocol_version
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
            headers=self._request_headers("text/event-stream"),
        )
        if r.status_code >= 400:
            return JsonRpcResponse(id=req.id, error={"code": r.status_code, "message": r.reason_phrase})
        resp = _parse_sse(r.text)
        self._capture_protocol_state(req, r.headers, resp)
        return resp


class StreamableHttpTransport(HttpSseTransport):
    """Modern transport: single bidi POST/JSON, server may answer JSON or SSE."""

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if not self._client:
            raise RuntimeError("Transport not open")
        r = self._client.post(
            self.config.url,
            json=req.to_dict(),
            headers=self._request_headers("application/json, text/event-stream"),
        )
        if r.status_code >= 400:
            return JsonRpcResponse(id=req.id, error={"code": r.status_code, "message": r.reason_phrase})
        resp = self._decode(r)
        self._capture_protocol_state(req, r.headers, resp)
        return resp

    @staticmethod
    def _decode(r: httpx.Response) -> JsonRpcResponse:
        """Decode a body the server may have framed as SSE, JSON, or neither."""
        if "text/event-stream" in r.headers.get("content-type", ""):
            return _parse_sse(r.text)
        # Trust nothing: a server may send SSE without the header, or junk.
        try:
            return JsonRpcResponse.from_dict(r.json())
        except (ValueError, TypeError):
            return _parse_sse(r.text)


@contextmanager
def open_http(config: HttpConfig, streamable: bool = True) -> Iterator[HttpSseTransport]:
    t: HttpSseTransport = StreamableHttpTransport(config) if streamable else HttpSseTransport(config)
    t.open()
    try:
        yield t
    finally:
        t.close()
