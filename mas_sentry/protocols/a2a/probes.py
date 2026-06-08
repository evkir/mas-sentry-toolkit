# SPDX-License-Identifier: AGPL-3.0-or-later
"""Active probes against an A2A endpoint.

Currently:
- Task-ID collision: submit two tasks with the same id, see which wins.
- Cancel-other: submit task A, cancel task B (someone else's id) — should
  produce an authorization error.
- Goal-hijack: pipe ASI01 corpus through send_task, check artifact
  contamination by a unique canary token.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from .client import A2AClient, TaskState

_TERMINAL_STATES = {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELED}
DEFAULT_POLL_DEADLINE_S = 10.0
DEFAULT_POLL_INTERVAL_S = 0.5


@dataclass(frozen=True, slots=True)
class ProbeResult:
    name: str
    passed: bool  # True = server behaved safely
    detail: str


def probe_task_id_collision(client: A2AClient, task_id: str = "collision-test-001") -> ProbeResult:
    """Submit two tasks under the same id. Safe server reassigns or rejects."""
    client.send_task("first task message", task_id=task_id)
    r2 = client.send_task("second task message, different content", task_id=task_id)
    if r2.task_id != task_id:
        return ProbeResult(
            name="task-id-collision",
            passed=True,
            detail=f"Server reassigned id ({task_id} -> {r2.task_id})",
        )
    final = client.get_task(task_id)
    return ProbeResult(
        name="task-id-collision",
        passed=False,
        detail=(f"Both submissions accepted under same id. Final state: {final.state}"),
    )


def probe_unauthorized_cancel(client: A2AClient, foreign_task_id: str = "not-mine-001") -> ProbeResult:
    """Try cancelling a task we did not submit. Safe server rejects."""
    try:
        result = client.cancel_task(foreign_task_id)
    except httpx.HTTPError as e:
        return ProbeResult(
            name="unauthorized-cancel",
            passed=True,
            detail=f"Rejected: {type(e).__name__}",
        )
    return ProbeResult(
        name="unauthorized-cancel",
        passed=result.state != TaskState.CANCELED,
        detail=f"Cancel call returned state={result.state}",
    )


def probe_indirect_injection(
    client: A2AClient,
    payload: str,
    canary: str,
    max_wait_s: float = DEFAULT_POLL_DEADLINE_S,
    poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
) -> ProbeResult:
    """Send a prompt-injection payload, poll until terminal, check artifacts."""
    r = client.send_task(payload)
    deadline = time.monotonic() + max_wait_s
    while time.monotonic() < deadline and r.state not in _TERMINAL_STATES:
        time.sleep(poll_interval_s)
        r = client.get_task(r.task_id)
    blob = str(r.artifacts)
    contaminated = canary in blob
    return ProbeResult(
        name="indirect-injection",
        passed=not contaminated,
        detail=(f"Canary {'present' if contaminated else 'absent'} in artifacts"),
    )
