# SPDX-License-Identifier: AGPL-3.0-or-later
"""A2A client speaking the JSON-RPC 2.0 binding.

This is the most common real-world deployment per A2A tooling vendor
guidance, and v0.3.x was JSON-RPC-only. We implement only the surface we
need to test:

- /.well-known/agent-card.json | /.well-known/agent.json (card discovery)
- submit / poll / cancel a task (JSON-RPC methods; spelled SendMessage,
  GetTask and CancelTask in v1.0 and message/send, tasks/get and
  tasks/cancel in v0.3.x)

Requests POST a {"jsonrpc": "2.0", "id", "method", "params"} envelope. The
target URL is resolved from the discovered AgentCard's declared interfaces
(v1.0 supportedInterfaces[], or v0.3.x url/preferredTransport/
additionalInterfaces) rather than always hitting `base_url` - see
_resolve_jsonrpc_endpoint. JSON-RPC method names are NOT shared between v0.3 and
v1.0: v1.0 renamed each one to its gRPC service-method spelling and gates
them behind an A2A-Version header, so the dialect is resolved from the
discovered card - see _resolve_protocol_version.
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
    AUTH_REQUIRED = "auth-required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


PROTOCOL_VERSION_1_0 = "1.0"
PROTOCOL_VERSION_0_3 = "0.3"

# A2A v1.0 renamed every JSON-RPC method to its gRPC service-method spelling
# and gates them behind a version header; v0.3.x used slash-separated names
# and no header. The two vocabularies are disjoint, so a client that guesses
# wrong gets -32601 Method not found on every call rather than a soft
# degradation. See _resolve_protocol_version for how the dialect is picked.
_METHODS = {
    PROTOCOL_VERSION_1_0: {"send": "SendMessage", "get": "GetTask", "cancel": "CancelTask"},
    PROTOCOL_VERSION_0_3: {"send": "message/send", "get": "tasks/get", "cancel": "tasks/cancel"},
}
# Role is a proto enum in v1.0 and a lowercase string literal in v0.3.x.
_USER_ROLE = {PROTOCOL_VERSION_1_0: "ROLE_USER", PROTOCOL_VERSION_0_3: "user"}
# Servers read the dialect from this header; per the v1.0 spec an absent or
# empty header means v0.3, which is why it is only sent for v1.0.
VERSION_HEADER = "A2A-Version"

_V1_STATE_PREFIX = "TASK_STATE_"


def _normalize_task_state(raw: str) -> TaskState:
    """Map a v1.0 or legacy v0.3.x task state string onto the shared enum.

    v1.0 renamed every value to SCREAMING_SNAKE_CASE with a TASK_STATE_
    prefix (e.g. "completed" -> "TASK_STATE_COMPLETED"); v0.3.x used plain
    kebab-case. Strip the prefix and lowercase/dash it back to the legacy
    spelling so one enum covers both generations without duplicating members.
    v1.0 also adds TASK_STATE_UNSPECIFIED, which has no legacy equivalent and
    folds onto UNKNOWN, same as any value neither shape recognizes.
    """
    if raw.startswith(_V1_STATE_PREFIX):
        legacy = raw[len(_V1_STATE_PREFIX) :].lower().replace("_", "-")
        if legacy == "unspecified":
            return TaskState.UNKNOWN
        try:
            return TaskState(legacy)
        except ValueError:
            return TaskState.UNKNOWN
    try:
        return TaskState(raw)
    except ValueError:
        return TaskState.UNKNOWN


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


class A2AUnsupportedBindingError(RuntimeError):
    """The discovered AgentCard declares interfaces/transports, none of them JSON-RPC.

    Raised only when the card actually says something ("here is what I
    support, and it isn't this") - a card with no interface information at
    all is not treated as a refusal, since that is indistinguishable from a
    minimal/legacy card that never described its transport.
    """


def _resolve_jsonrpc_endpoint(data: dict[str, Any]) -> str | None:
    """Pick the JSON-RPC endpoint URL a discovered AgentCard declares.

    v1.0 cards list every binding+URL combination in supportedInterfaces[];
    order is preference, not binding, so the first entry may well be gRPC or
    HTTP+JSON - every entry is scanned for one advertising "JSONRPC" rather
    than trusting supportedInterfaces[0]. v0.3.x cards have no
    supportedInterfaces at all: a single top-level `url` plus an optional
    `preferredTransport` (defaults to JSONRPC when absent, per spec) and
    `additionalInterfaces[]` for alternates.

    Returns the endpoint URL, or None if the card carries no interface/
    transport information at all (caller should fall back to base_url - this
    is not a refusal, just an absence of data, e.g. a minimal test card).
    Raises A2AUnsupportedBindingError if the card explicitly declares
    interfaces/transports and none of them is JSON-RPC - that is a real
    signal worth surfacing, not something to silently paper over.
    """
    interfaces = data.get("supportedInterfaces")
    if isinstance(interfaces, list) and interfaces:
        for iface in interfaces:
            if isinstance(iface, dict) and iface.get("protocolBinding") == "JSONRPC":
                url = iface.get("url")
                if isinstance(url, str) and url:
                    return url
        bindings = sorted(
            str(i.get("protocolBinding")) for i in interfaces if isinstance(i, dict) and i.get("protocolBinding")
        )
        raise A2AUnsupportedBindingError(
            f"AgentCard.supportedInterfaces declares no JSONRPC binding (offers: {bindings})"
        )

    preferred = data.get("preferredTransport")
    additional = data.get("additionalInterfaces")
    if preferred or additional:
        url = data.get("url")
        if (preferred or "JSONRPC") == "JSONRPC" and isinstance(url, str) and url:
            return url
        for iface in additional or []:
            if isinstance(iface, dict) and iface.get("transport") == "JSONRPC":
                alt_url = iface.get("url")
                if isinstance(alt_url, str) and alt_url:
                    return alt_url
        raise A2AUnsupportedBindingError(
            f"AgentCard declares preferredTransport={preferred!r} with no JSONRPC alternative in additionalInterfaces"
        )

    return None


def _resolve_protocol_version(data: dict[str, Any]) -> str:
    """Pick the A2A generation a discovered AgentCard speaks.

    supportedInterfaces[] exists only in v1.0, so its presence is itself the
    signal; when the matching JSONRPC entry also carries an explicit
    protocolVersion that value wins, since an operator may publish a v1.0
    card that still fronts a 0.3 endpoint during a migration. A card with no
    supportedInterfaces is the v0.3.x shape (top-level url plus optional
    preferredTransport), and an undiscovered card resolves to v0.3 as well -
    the reference implementation reads an absent version header as 0.3, so
    matching that default keeps us wrong in the same direction a server is.
    """
    interfaces = data.get("supportedInterfaces")
    if not isinstance(interfaces, list) or not interfaces:
        return PROTOCOL_VERSION_0_3
    for iface in interfaces:
        if isinstance(iface, dict) and iface.get("protocolBinding") == "JSONRPC":
            declared = iface.get("protocolVersion")
            if isinstance(declared, str) and declared.startswith(PROTOCOL_VERSION_0_3):
                return PROTOCOL_VERSION_0_3
            break
    return PROTOCOL_VERSION_1_0


def _unwrap_send_result(result: dict[str, Any], version: str) -> dict[str, Any]:
    """Return the Task object out of a send response.

    v1.0's SendMessageResponse is a oneof, so a task-producing agent answers
    {"task": {...}} while an agent replying inline answers {"message": {...}}.
    v0.3.x returns the Task flat. Only the send response is wrapped - GetTask
    and CancelTask return the Task at the top level in both generations, so
    unwrapping unconditionally would blank those out.
    """
    if version == PROTOCOL_VERSION_1_0:
        task = result.get("task")
        if isinstance(task, dict):
            return task
    return result


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
        self._card_raw: dict[str, Any] | None = None
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
        self._card_raw = data
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
        """Submit a message and return the resulting Task.

        `task_id` labels the outgoing message, not the task. A2A has no field
        that lets a client choose the id of a task it is creating in either
        generation - Message.taskId references an already existing task, and a
        spec-compliant server answers -32001 for one it has never issued. Task
        ids are server-assigned, so callers that need to correlate submissions
        should read the id back off the returned TaskResult.
        """
        mid = task_id or secrets.token_hex(8)
        version = self._protocol_version()
        params: dict[str, Any] = {
            "message": {
                "messageId": mid,
                "role": _USER_ROLE[version],
                "parts": [{"text": message}],
            },
        }
        result = self._rpc_call(_METHODS[version]["send"], params)
        return self._parse_task(_unwrap_send_result(result, version))

    def get_task(self, task_id: str) -> TaskResult:
        result = self._rpc_call(_METHODS[self._protocol_version()]["get"], {"id": task_id})
        return self._parse_task(result)

    def cancel_task(self, task_id: str) -> TaskResult:
        result = self._rpc_call(_METHODS[self._protocol_version()]["cancel"], {"id": task_id})
        return self._parse_task(result)

    def _rpc_call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Issue a JSON-RPC 2.0 request and return its `result` object.

        A2A's JSON-RPC binding returns HTTP 200 for protocol-level errors
        too, with the failure in the response body's `error` field - only a
        transport/HTTP failure surfaces as a non-2xx status. Both are
        surfaced to the caller, as httpx.HTTPError and A2ARpcError
        respectively, so probes can tell "rejected" from "unreachable".
        """
        url = self._rpc_endpoint()
        req_id = secrets.token_hex(8)
        body = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
        headers = {}
        version = self._protocol_version()
        if version == PROTOCOL_VERSION_1_0:
            headers[VERSION_HEADER] = version
        r = self._client.post(url, json=body, headers=headers)
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

    def _rpc_endpoint(self) -> str:
        """Resolve where to send JSON-RPC calls.

        Uses the card's declared interface if one was discovered, else
        `base_url` (no discovery run yet, e.g. a caller driving send/get/
        cancel directly - existing behavior, preserved as the fallback).
        """
        if self._card_raw is None:
            return self.base_url
        return _resolve_jsonrpc_endpoint(self._card_raw) or self.base_url

    def _protocol_version(self) -> str:
        """Resolve which A2A generation to speak, from the discovered card."""
        if self._card_raw is None:
            return PROTOCOL_VERSION_0_3
        return _resolve_protocol_version(self._card_raw)

    @staticmethod
    def _parse_task(data: dict[str, Any]) -> TaskResult:
        raw_state = data.get("status", {}).get("state", "unknown")
        state = _normalize_task_state(raw_state) if isinstance(raw_state, str) else TaskState.UNKNOWN
        return TaskResult(
            task_id=data.get("id", ""),
            state=state,
            artifacts=data.get("artifacts", []),
            raw=data,
        )
