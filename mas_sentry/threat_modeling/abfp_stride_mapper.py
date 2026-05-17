# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Maps ABFP anomaly findings to STRIDE threat categories automatically.
"""
from typing import Any
from .stride import STRIDECategory, STRIDEThreat


ABFP_TO_STRIDE: dict[str, STRIDECategory] = {
    "duplicate_client_id":      STRIDECategory.SPOOFING,
    "behavioral_clone":         STRIDECategory.SPOOFING,
    "topic_privilege_escalation": STRIDECategory.ELEVATION_OF_PRIVILEGE,
    "new_topic_emergence":      STRIDECategory.ELEVATION_OF_PRIVILEGE,
    "payload_size_spike":       STRIDECategory.DENIAL_OF_SERVICE,
    "message_flood":            STRIDECategory.DENIAL_OF_SERVICE,
    "timing_anomaly":           STRIDECategory.TAMPERING,
    "retained_message_poison":  STRIDECategory.TAMPERING,
    "wildcard_enumeration":     STRIDECategory.INFO_DISCLOSURE,
    "no_message_signing":       STRIDECategory.REPUDIATION,
}


def map_finding_to_stride(finding: dict[str, Any]) -> STRIDEThreat | None:
    """Convert a single ABFP finding dict into a STRIDEThreat object."""
    finding_type = finding.get("type", "")
    category = ABFP_TO_STRIDE.get(finding_type)
    if not category:
        return None

    return STRIDEThreat(
        category=category,
        title=f"ABFP: {finding.get('title', finding_type)}",
        description=finding.get("description", "Detected by ABFP engine."),
        mitigation=finding.get("mitigation", "Review ABFP anomaly report."),
        severity=finding.get("severity", "MEDIUM"),
    )


def map_session_findings(findings: list[dict[str, Any]]) -> list[STRIDEThreat]:
    """Map all findings from a scan session to STRIDE threats."""
    threats = []
    for f in findings:
        threat = map_finding_to_stride(f)
        if threat:
            threats.append(threat)
    return threats
