# SPDX-License-Identifier: AGPL-3.0-or-later
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CapturedMessage:
    topic: str
    payload: bytes
    qos: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_client_id: Optional[str] = None

    def payload_str(self) -> str:
        try:
            return self.payload.decode("utf-8")
        except Exception:
            return repr(self.payload)

    def payload_size(self) -> int:
        return len(self.payload)


class BaseProtocolAnalyzer(ABC):
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.messages: List[CapturedMessage] = []
        self.is_running = False

    @abstractmethod
    def connect(self) -> bool:
        pass

    @abstractmethod
    def disconnect(self):
        pass

    @abstractmethod
    def capture(self, duration: int) -> List[CapturedMessage]:
        pass

    @abstractmethod
    def enumerate_topics(self) -> List[str]:
        pass

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_messages": len(self.messages),
            "unique_topics": len(set(m.topic for m in self.messages)),
            "total_bytes": sum(m.payload_size() for m in self.messages),
        }

    def filter_by_topic(self, pattern: str) -> List[CapturedMessage]:
        return [m for m in self.messages if m.topic.startswith(pattern)]

    def filter_by_size(self, min_bytes: int = 0, max_bytes: int = 999999) -> List[CapturedMessage]:
        return [m for m in self.messages
                if min_bytes <= m.payload_size() <= max_bytes]

    def unique_topic_list(self) -> List[str]:
        return sorted(set(m.topic for m in self.messages))

    def largest_messages(self, n: int = 5) -> List[CapturedMessage]:
        return sorted(self.messages, key=lambda m: m.payload_size(), reverse=True)[:n]

    def to_dict_list(self) -> List[Dict[str, Any]]:
        return [
            {
                "topic":     m.topic,
                "payload":   m.payload_str(),
                "size":      m.payload_size(),
                "qos":       m.qos,
                "timestamp": m.timestamp.isoformat(),
                "client_id": m.source_client_id,
            }
            for m in self.messages
        ]
