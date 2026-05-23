# SPDX-License-Identifier: AGPL-3.0-or-later
"""Map ABFP anomalies to STRIDE + ASI tags."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ThreatTag:
    stride: str
    asi: str  # e.g. "ASI10"
    cwe: str | None = None


ANOMALY_TAGS: dict[str, ThreatTag] = {
    "rogue_agent": ThreatTag(stride="Spoofing+EoP", asi="ASI10", cwe="CWE-940"),
    "impersonation": ThreatTag(stride="Spoofing", asi="ASI03", cwe="CWE-290"),
    "topic_privilege_escalation": ThreatTag(stride="Elevation of Privilege", asi="ASI03"),
    "silent_agent": ThreatTag(stride="Denial of Service", asi="ASI05"),
    "payload_drift": ThreatTag(stride="Tampering", asi="ASI04"),
    "new_subscription_to_sensitive": ThreatTag(stride="Information Disclosure", asi="ASI03"),
}


def tag_for(anomaly_type: str) -> ThreatTag | None:
    return ANOMALY_TAGS.get(anomaly_type)
