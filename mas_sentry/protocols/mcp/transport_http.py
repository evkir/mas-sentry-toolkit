# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP+SSE and streamable-HTTP transports."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import httpx

from .jsonrpc import JsonRpcRequest, JsonRpcResponse


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

    def open(self) -> None:
        self._client = httpx.Client(
            headers=self.config.headers or {},
            timeout=self.config.timeout,
            verify=self.config.verify_tls,
        )

    def close(self) -> None:
        if self._client:
            self._client.close()
        self._client = None

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if not self._client:
            raise RuntimeError("Transport not open")
        body = req.encode()
        r = self._client.post(
            self.config.url,
            content=body,
            headers={"content-type": "application/json", "accept": "text/event-stream"},
        )
        if r.status_code >= 400:
            return JsonRpcResponse(id=req.id, error={"code": r.status_code, "message": r.reason_phrase})
        return _parse_sse(r.text)


class StreamableHttpTransport(HttpSseTransport):
    """Modern transport: single bidi POST/JSON, server may answer JSON or SSE."""

    def send(self, req: JsonRpcRequest) -> JsonRpcResponse:
        if not self._client:
            raise RuntimeError("Transport not open")
        r = self._client.post(
            self.config.url,
            json=req.to_dict(),
            headers={
                "content-type": "application/json",
                "accept": "application/json, text/event-stream",
            },
        )
        if r.status_code >= 400:
            return JsonRpcResponse(id=req.id, error={"code": r.status_code, "message": r.reason_phrase})
        ctype = r.headers.get("content-type", "")
        if "text/event-stream" in ctype:
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
