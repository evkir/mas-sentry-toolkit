# SPDX-License-Identifier: AGPL-3.0-or-later
"""A2A client speaking the JSON-RPC 2.0 binding.

This is the most common real-world deployment per A2A tooling vendor
guidance, and v0.3.x was JSON-RPC-only. We implement only the surface we
need to test:

- /.well-known/agent-card.json | /.well-known/agent.json (card discovery)
- message/send  (submit, JSON-RPC method)
- tasks/get     (poll, JSON-RPC method)
- tasks/cancel  (JSON-RPC method)

Requests POST a {"jsonrpc": "2.0", "id", "method", "params"} envelope to
`base_url` directly - we do not yet resolve AgentCard.supportedInterfaces[]
to pick a per-interface URL/binding (v1.0 lets an agent advertise several);
that is a separate, larger piece of work. JSON-RPC method names are shared
between v0.3 and v1.0 (only the params/result payload shapes moved - see
TaskState/Role/Part handling below), so no version branch is needed here.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import StrEnum
from types import TracebackType
from typing import Any

import httpx

from mas_sentry.core.scope import assert_in_scope


class TaskState(StrEnum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"
    UNKNOWN = "unknown"


class A2ARpcError(RuntimeError):
    """A JSON-RPC-level error returned by the agent (HTTP 200, error in body).

    A2A's JSON-RPC binding signals protocol-level rejections (task not
    found, not cancelable, etc.) this way, not via HTTP status - a bare
    raise_for_status() never sees them. Callers that need to distinguish
    "the agent properly rejected this" from "the transport failed" should
    catch this alongside httpx.HTTPError.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"JSON-RPC error {code}: {message}")


@dataclass(slots=True)
class AgentCard:
    name: str
    description: str
    url: str
    version: str = ""
    skills: list[dict[str, Any]] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    authentication: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TaskResult:
    task_id: str
    state: TaskState
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class A2AClient:
    """Minimal HTTP+JSON client for the Google A2A protocol.

    Pass `transport=httpx.MockTransport(...)` for offline tests.
    """

    def __init__(
        self,
        base_url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 15.0,
        verify_tls: bool = True,
        transport: httpx.BaseTransport | None = None,
        confirmed: bool = False,
    ) -> None:
        if transport is None:
            assert_in_scope(base_url, confirmed=confirmed)
        self.base_url = base_url.rstrip("/")
        self._client = httpx.Client(
            headers=headers or {},
            timeout=timeout,
            verify=verify_tls,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> A2AClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def discover(self) -> AgentCard:
        data = self._fetch_card_json()
        if not isinstance(data, dict):
            raise httpx.DecodingError(f"AgentCard JSON must be an object, got {type(data).__name__}")
        return AgentCard(
            name=data.get("name", ""),
            description=data.get("description", ""),
            url=data.get("url", self.base_url),
            version=data.get("version", ""),
            skills=data.get("skills", []),
            capabilities=data.get("capabilities", {}),
            authentication=data.get("authentication", {}),
            raw=data,
        )

    def _fetch_card_json(self) -> Any:
        """Fetch the raw AgentCard JSON, trying the A2A v1.0 well-known URI first.

        A2A v1.0 (stable since April 2026, Linux Foundation) moved discovery
        from /.well-known/agent.json (v0.3.x) to /.well-known/agent-card.json.
        Real targets are a mixed fleet during the migration window, so a plain
        404 on the current path falls back to the legacy one rather than
        hard-rejecting an agent that has not upgraded yet. Any other transport
        failure (connection error, 5xx, etc.) propagates immediately - only
        "not found" is treated as a version signal worth retrying.
        """
        r = self._client.get(f"{self.base_url}/.well-known/agent-card.json")
        if r.status_code == 404:
            r = self._client.get(f"{self.base_url}/.well-known/agent.json")
        r.raise_for_status()
        return r.json()

    def send_task(self, message: str, task_id: str | None = None) -> TaskResult:
        tid = task_id or secrets.token_hex(8)
        params = {
            "id": tid,
            "message": {
                "role": "ROLE_USER",
                "parts": [{"text": message}],
            },
        }
        result = self._rpc_call("message/send", params)
        return self._parse_task(result)

    def get_task(self, task_id: str) -> TaskResult:
        result = self._rpc_call("tasks/get", {"id": task_id})
        return self._parse_task(result)

    def cancel_task(self, task_id: str) -> TaskResult:
        result = self._rpc_call("tasks/cancel", {"id": task_id})
        return self._parse_task(result)

    def _rpc_call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Issue a JSON-RPC 2.0 request and return its `result` object.

        A2A's JSON-RPC binding returns HTTP 200 for protocol-level errors
        too, with the failure in the response body's `error` field - only a
        transport/HTTP failure surfaces as a non-2xx status. Both are
        surfaced to the caller, as httpx.HTTPError and A2ARpcError
        respectively, so probes can tell "rejected" from "unreachable".
        """
        req_id = secrets.token_hex(8)
        body = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        r = self._client.post(self.base_url, json=body)
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            err = data["error"] or {}
            raise A2ARpcError(
                code=err.get("code", 0),
                message=err.get("message", "unknown JSON-RPC error"),
                data=err.get("data"),
            )
        result = data.get("result")
        if not isinstance(result, dict):
            raise httpx.DecodingError(f"JSON-RPC result must be an object, got {type(result).__name__}")
        return result

    @staticmethod
    def _parse_task(data: dict[str, Any]) -> TaskResult:
        try:
            state = TaskState(data.get("status", {}).get("state", "unknown"))
        except ValueError:
            state = TaskState.UNKNOWN
        return TaskResult(
            task_id=data.get("id", ""),
            state=state,
            artifacts=data.get("artifacts", []),
            raw=data,
        )
