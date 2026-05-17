# SPDX-License-Identifier: AGPL-3.0-or-later
"""
mas_sentry/agents/profiles.py
AgentProfile dataclass — behavioral fingerprint of a single MAS agent.
DAY 15 — Commit 1
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class MessageEvent:
    topic: str
    payload_size: int
    timestamp: datetime
    qos: int = 0
    retain: bool = False


@dataclass
class AgentProfile:
    """
    Behavioral fingerprint of one MQTT agent (identified by client_id).
    Built passively by observing traffic — no active probing.
    """

    client_id: str
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)

    # Topic behavior
    topics_pub: set[str] = field(default_factory=set)
    topics_sub: set[str] = field(default_factory=set)

    # Message events
    message_events: list[MessageEvent] = field(default_factory=list)

    # Computed metrics (filled by analyzer)
    avg_interval_s: float = 0.0
    avg_payload_b: float = 0.0
    entropy_score: float = 0.0
    anomaly_score: int = 0  # 0-100

    def update_seen(self, ts: datetime) -> None:
        if ts > self.last_seen:
            self.last_seen = ts

    def message_count(self) -> int:
        return len(self.message_events)

    def active_seconds(self) -> float:
        if not self.message_events:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds()

    def compute_avg_interval(self) -> float:
        """Average time between messages in seconds."""
        events = sorted(self.message_events, key=lambda e: e.timestamp)
        if len(events) < 2:
            return 0.0
        intervals = [(events[i].timestamp - events[i - 1].timestamp).total_seconds() for i in range(1, len(events))]
        self.avg_interval_s = sum(intervals) / len(intervals)
        return self.avg_interval_s

    def compute_avg_payload(self) -> float:
        """Average payload size in bytes."""
        if not self.message_events:
            return 0.0
        self.avg_payload_b = sum(e.payload_size for e in self.message_events) / len(self.message_events)
        return self.avg_payload_b

    def to_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "topics_pub": list(self.topics_pub),
            "topics_sub": list(self.topics_sub),
            "message_count": self.message_count(),
            "avg_interval_s": self.avg_interval_s,
            "avg_payload_b": self.avg_payload_b,
            "entropy_score": self.entropy_score,
            "anomaly_score": self.anomaly_score,
        }
