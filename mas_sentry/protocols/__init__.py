# SPDX-License-Identifier: AGPL-3.0-or-later
from .base import BaseProtocolAnalyzer, CapturedMessage

SUPPORTED_PROTOCOLS = {
    "mqtt": None,  # MQTTAnalyzer added Day 5
}


def get_analyzer(protocol: str, host: str, port: int) -> BaseProtocolAnalyzer:
    from .mqtt_analyzer import MQTTAnalyzer

    SUPPORTED_PROTOCOLS["mqtt"] = MQTTAnalyzer
    cls = SUPPORTED_PROTOCOLS.get(protocol.lower())
    if not cls:
        raise ValueError(f"Unsupported protocol: {protocol}. Choose from: {list(SUPPORTED_PROTOCOLS)}")
    return cls(host, port)


__all__ = ["BaseProtocolAnalyzer", "CapturedMessage", "get_analyzer"]
