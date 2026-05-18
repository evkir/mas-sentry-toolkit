# SPDX-License-Identifier: AGPL-3.0-or-later
"""MessageObserver — per-agent ring-buffer of MessageEvent records."""
from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from threading import RLock
from time import monotonic
from typing import Self

DEFAULT_BUFFER_SIZE = 1024


@dataclass(frozen=True, slots=True)
class MessageEvent:
    """A single observed message. Frozen — events are append-only."""

    agent_id: str
    topic: str
    payload_size: int
    qos: int
    retain: bool
    timestamp: float  # monotonic seconds since process start
    payload_hash: str = ""  # sha1 of payload, optional, for dedup

    @classmethod
    def now(cls, agent_id: str, topic: str, payload: bytes, qos: int = 0, retain: bool = False) -> Self:
        import hashlib
        return cls(
            agent_id=agent_id,
            topic=topic,
            payload_size=len(payload),
            qos=qos,
            retain=retain,
            timestamp=monotonic(),
            payload_hash=hashlib.sha1(payload, usedforsecurity=False).hexdigest()[:16],
        )


class MessageObserver:
    """Thread-safe per-agent ring buffer. Bounded memory by design."""

    def __init__(self, max_per_agent: int = DEFAULT_BUFFER_SIZE) -> None:
        self._buffers: dict[str, deque[MessageEvent]] = {}
        self._lock = RLock()
        self._max = max_per_agent
        self._total_observed = 0

    def record(self, event: MessageEvent) -> None:
        with self._lock:
            buf = self._buffers.get(event.agent_id)
            if buf is None:
                buf = deque(maxlen=self._max)
                self._buffers[event.agent_id] = buf
            buf.append(event)
            self._total_observed += 1

    def agent_ids(self) -> list[str]:
        with self._lock:
            return list(self._buffers.keys())

    def events_for(self, agent_id: str) -> list[MessageEvent]:
        with self._lock:
            buf = self._buffers.get(agent_id)
            return list(buf) if buf else []

    def count_for(self, agent_id: str) -> int:
        with self._lock:
            buf = self._buffers.get(agent_id)
            return len(buf) if buf else 0

    def __iter__(self) -> Iterator[tuple[str, list[MessageEvent]]]:
        with self._lock:
            snap = {aid: list(buf) for aid, buf in self._buffers.items()}
        yield from snap.items()

    @property
    def total_observed(self) -> int:
        with self._lock:
            return self._total_observed
