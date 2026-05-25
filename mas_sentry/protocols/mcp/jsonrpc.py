# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal JSON-RPC 2.0 codec. Lenient on input by design (we test broken servers)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Self


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
    def from_dict(cls, data: dict[str, Any]) -> Self:
        return cls(
            id=data.get("id"),
            result=data.get("result"),
            error=data.get("error"),
            jsonrpc=data.get("jsonrpc", "2.0"),
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
