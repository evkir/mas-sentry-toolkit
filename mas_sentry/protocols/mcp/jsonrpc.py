# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal JSON-RPC 2.0 codec. Lenient on input by design (we test broken servers).

Lenient had a hole in it. `error` is typed as a JSON-RPC error object and seven
places read it as one, but the decoder put whatever the target sent into that
field - and an OAuth resource server does not send an object. RFC 6750 Section
3 specifies `{"error": "invalid_token", ...}`, a string, which is what every
OAuth-guarded MCP server answers with and what CVE-2026-59822 made a population
rather than a curiosity. A scan of such a target died on `.get` before any check
ran, leaving no report at all.

So the type is made true here, where the lie enters, instead of being guarded at
each reader: a field whose declared type holds is a guarantee, while seven
`isinstance` checks are seven chances to forget the eighth.

Two shapes arrive and both are normalised rather than dropped (R-2.1):

  a non-object `error` inside a readable message, which keeps its text
  a document that is valid JSON but not a message at all - `null`, a bare
  string, a list, a number, which a proxy or an error page can produce

Both normalise to `code: None`, meaning the target sent no usable JSON-RPC code.
That is not a new shape for readers: the STDIO transport already reports its own
process failures as an error object without a code, and every reader compares
the code against a constant, which None fails correctly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Self

# A message written by the target. Long enough for any reason a server states,
# and short enough that a body meant to exhaust the host does not travel with
# every finding into the report.
MAX_ERROR_CHARS = 200


def _clip(value: Any) -> str:
    """Whatever the target sent, as a string the report can carry."""
    return str(value)[:MAX_ERROR_CHARS]


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.data = data


@dataclass(slots=True)
class JsonRpcRequest:
    method: str
    params: dict[str, Any] | list[Any] | None = None
    id: int | str | None = None
    jsonrpc: str = "2.0"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"jsonrpc": self.jsonrpc, "method": self.method}
        if self.params is not None:
            d["params"] = self.params
        if self.id is not None:
            d["id"] = self.id
        return d

    def encode(self) -> bytes:
        return json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")


@dataclass(slots=True)
class JsonRpcResponse:
    id: int | str | None
    result: Any = None
    error: dict[str, Any] | None = None
    jsonrpc: str = "2.0"
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.error is not None

    @classmethod
    def from_dict(cls, data: Any) -> Self:
        """Read one message, making `error` hold the type it declares.

        Takes `Any` rather than a dict because both callers hand over whatever
        the target sent: `decode` passes the parsed document, and the HTTP
        transport passes `response.json()` directly.
        """
        if not isinstance(data, dict):
            return cls(
                id=None,
                error={"code": None, "message": f"not a JSON-RPC message: {_clip(data)}"},
                raw={"_raw": _clip(data)},
            )
        error = data.get("error")
        if error is not None and not isinstance(error, dict):
            # Kept verbatim in the message: for RFC 6750 this string is the
            # whole reason the target gave, and `raw` holds the rest of the body.
            error = {"code": None, "message": _clip(error)}
        return cls(
            id=data.get("id"),
            result=data.get("result"),
            error=error,
            jsonrpc=data.get("jsonrpc", "2.0") if isinstance(data.get("jsonrpc", "2.0"), str) else "2.0",
            raw=data,
        )

    @classmethod
    def decode(cls, raw: bytes | str) -> Self:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        try:
            return cls.from_dict(json.loads(raw))
        except json.JSONDecodeError as e:
            return cls(id=None, error={"code": -32700, "message": f"Parse error: {e}"}, raw={"_raw": raw})


class JsonRpcCodec:
    """Stateless helpers; transports do their own framing."""

    @staticmethod
    def request(method: str, params: dict[str, Any] | list[Any] | None = None, req_id: int | str = 1) -> JsonRpcRequest:
        return JsonRpcRequest(method=method, params=params, id=req_id)

    @staticmethod
    def notification(method: str, params: dict[str, Any] | list[Any] | None = None) -> JsonRpcRequest:
        return JsonRpcRequest(method=method, params=params, id=None)
