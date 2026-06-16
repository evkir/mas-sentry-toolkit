# SPDX-License-Identifier: AGPL-3.0-or-later
"""A2A is HTTP+JSON. We implement only the surface we need to test:

- /.well-known/agent.json (agent card discovery)
- /tasks/send  (submit)
- /tasks/get   (poll)
- /tasks/cancel
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
        r = self._client.get(f"{self.base_url}/.well-known/agent.json")
        r.raise_for_status()
        data = r.json()
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

    def send_task(self, message: str, task_id: str | None = None) -> TaskResult:
        tid = task_id or secrets.token_hex(8)
        body = {
            "id": tid,
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": message}],
            },
        }
        r = self._client.post(f"{self.base_url}/tasks/send", json=body)
        r.raise_for_status()
        return self._parse_task(r.json())

    def get_task(self, task_id: str) -> TaskResult:
        r = self._client.post(f"{self.base_url}/tasks/get", json={"id": task_id})
        r.raise_for_status()
        return self._parse_task(r.json())

    def cancel_task(self, task_id: str) -> TaskResult:
        r = self._client.post(f"{self.base_url}/tasks/cancel", json={"id": task_id})
        r.raise_for_status()
        return self._parse_task(r.json())

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
