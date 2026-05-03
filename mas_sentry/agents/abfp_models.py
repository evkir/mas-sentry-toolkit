"""
ABFP — Agent Behavioral Fingerprinting Protocol
Core data models: MessageEvent, AgentFingerprint, BehavioralBaseline
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone, timezone
import json


@dataclass
class MessageEvent:
    """Single captured message event from an agent"""
    topic: str
    payload_size: int
    timestamp: float
    qos: int = 0
    retain: bool = False
    payload_preview: str = ""

    def to_dict(self) -> Dict:
        return {
            "topic": self.topic,
            "payload_size": self.payload_size,
            "timestamp": self.timestamp,
            "qos": self.qos,
            "retain": self.retain,
        }


@dataclass
class TopicProfile:
    """Profile of a single topic used by an agent"""
    topic: str
    message_count: int = 0
    total_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    qos_levels: List[int] = field(default_factory=list)
    retain_count: int = 0

    @property
    def avg_payload_bytes(self) -> float:
        return self.total_bytes / self.message_count if self.message_count else 0

    @property
    def retain_ratio(self) -> float:
        return self.retain_count / self.message_count if self.message_count else 0


@dataclass
class TimingMetrics:
    """Timing cadence metrics for an agent"""
    mean_interval_ms: float = 0.0
    std_interval_ms: float = 0.0
    min_interval_ms: float = 0.0
    max_interval_ms: float = 0.0
    burst_detected: bool = False
    burst_threshold_ms: float = 50.0
    sample_count: int = 0

    def to_dict(self) -> Dict:
        return {
            "mean_interval_ms": round(self.mean_interval_ms, 2),
            "std_interval_ms": round(self.std_interval_ms, 2),
            "min_interval_ms": round(self.min_interval_ms, 2),
            "max_interval_ms": round(self.max_interval_ms, 2),
            "burst_detected": self.burst_detected,
            "sample_count": self.sample_count,
        }


@dataclass
class PayloadMetrics:
    """Payload signature metrics for an agent"""
    mean_size_bytes: float = 0.0
    std_size_bytes: float = 0.0
    min_size_bytes: int = 0
    max_size_bytes: int = 0
    entropy_score: float = 0.0
    encoding: str = "unknown"   # json / binary / plaintext / base64

    def to_dict(self) -> Dict:
        return {
            "mean_size_bytes": round(self.mean_size_bytes, 2),
            "std_size_bytes": round(self.std_size_bytes, 2),
            "min_size_bytes": self.min_size_bytes,
            "max_size_bytes": self.max_size_bytes,
            "entropy_score": round(self.entropy_score, 3),
            "encoding": self.encoding,
        }


@dataclass
class AgentFingerprint:
    """
    Complete behavioral fingerprint for a single inferred agent.
    Built from passive observation of MQTT traffic.
    This is the core ABFP output object.
    """
    agent_id: str
    first_seen: float
    last_seen: float

    # Raw data
    message_events: List[MessageEvent] = field(default_factory=list)
    topic_profiles: Dict[str, TopicProfile] = field(default_factory=dict)

    # Computed metrics (populated by ABFPFingerprinter)
    timing: TimingMetrics = field(default_factory=TimingMetrics)
    payload: PayloadMetrics = field(default_factory=PayloadMetrics)

    # ABFP scoring
    anomaly_score: float = 0.0        # 0.0 = normal, 100.0 = critical
    threat_flags: List[str] = field(default_factory=list)
    is_rogue: bool = False
    confidence: float = 0.0           # confidence in fingerprint (0-1)

    @property
    def message_count(self) -> int:
        return len(self.message_events)

    @property
    def unique_topics(self) -> List[str]:
        return list(self.topic_profiles.keys())

    @property
    def active_duration_seconds(self) -> float:
        return self.last_seen - self.first_seen

    def add_threat_flag(self, flag: str):
        if flag not in self.threat_flags:
            self.threat_flags.append(flag)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
            "active_duration_seconds": round(self.active_duration_seconds, 1),
            "message_count": self.message_count,
            "unique_topics": self.unique_topics,
            "timing": self.timing.to_dict(),
            "payload": self.payload.to_dict(),
            "anomaly_score": round(self.anomaly_score, 2),
            "threat_flags": self.threat_flags,
            "is_rogue": self.is_rogue,
            "confidence": round(self.confidence, 2),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


@dataclass
class BehavioralBaseline:
    """
    Saved behavioral baseline for a known-good agent.
    Used in Phase 3 (active probing) to detect deviations.
    Persisted to disk as JSON for cross-session comparison.
    """
    agent_id: str
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    fingerprints: List[Dict] = field(default_factory=list)
    known_topics: List[str] = field(default_factory=list)
    expected_interval_ms: float = 0.0
    expected_payload_size: float = 0.0
    expected_entropy: float = 0.0

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({
                "agent_id": self.agent_id,
                "created_at": self.created_at,
                "known_topics": self.known_topics,
                "expected_interval_ms": self.expected_interval_ms,
                "expected_payload_size": self.expected_payload_size,
                "expected_entropy": self.expected_entropy,
            }, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "BehavioralBaseline":
        with open(path) as f:
            data = json.load(f)
        return cls(**data)

    def deviation_score(self, fp: "AgentFingerprint") -> float:
        """
        Compute behavioral deviation score (0-100)
        between this baseline and a new fingerprint.
        Higher = more suspicious.
        """
        score = 0.0

        # New topics not in baseline → suspicious
        new_topics = set(fp.unique_topics) - set(self.known_topics)
        score += len(new_topics) * 15.0

        # Timing deviation
        if self.expected_interval_ms > 0:
            timing_dev = abs(
                fp.timing.mean_interval_ms - self.expected_interval_ms
            ) / self.expected_interval_ms
            score += min(timing_dev * 30.0, 30.0)

        # Payload size deviation
        if self.expected_payload_size > 0:
            payload_dev = abs(
                fp.payload.mean_size_bytes - self.expected_payload_size
            ) / self.expected_payload_size
            score += min(payload_dev * 20.0, 20.0)

        # Entropy deviation
        if self.expected_entropy > 0:
            entropy_dev = abs(
                fp.payload.entropy_score - self.expected_entropy
            ) / max(self.expected_entropy, 0.01)
            score += min(entropy_dev * 10.0, 10.0)

        return min(score, 100.0)
