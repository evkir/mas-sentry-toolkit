# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class STRIDECategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


@dataclass
class STRIDEThreat:
    threat_id: str
    category: STRIDECategory
    title: str
    description: str
    mitigation: str
    severity: str
    cvss_score: float
    cve_refs: Optional[List[str]] = field(default_factory=list)


MAS_THREAT_CATALOG = [
    STRIDEThreat(
        threat_id="MAS-S-001",
        category=STRIDECategory.SPOOFING,
        title="Agent Impersonation via MQTT Client ID Spoofing",
        description="MQTT does not verify client identity. Attacker sets any client_id.",
        mitigation="Implement mutual TLS. Validate client certificates against known agents.",
        severity="CRITICAL",
        cvss_score=9.1,
    ),
    STRIDEThreat(
        threat_id="MAS-S-002",
        category=STRIDECategory.SPOOFING,
        title="Behavioral Clone — Same Topics Different Timing",
        description="Attacker clones agent topic pattern but timing differs from baseline.",
        mitigation="Use ABFP timing deviation scoring to detect cloned agents.",
        severity="HIGH",
        cvss_score=8.2,
    ),
    STRIDEThreat(
        threat_id="MAS-T-001",
        category=STRIDECategory.TAMPERING,
        title="Retained Message Poisoning",
        description="Attacker publishes malicious retained message to command topic.",
        mitigation="Restrict publish permissions. Validate message schema and origin.",
        severity="HIGH",
        cvss_score=7.5,
    ),
    STRIDEThreat(
        threat_id="MAS-T-002",
        category=STRIDECategory.TAMPERING,
        title="Payload Injection via Unvalidated Input",
        description="Agent consumes unvalidated payload leading to command injection.",
        mitigation="Enforce strict payload schema validation on all subscribers.",
        severity="HIGH",
        cvss_score=7.8,
    ),
    STRIDEThreat(
        threat_id="MAS-R-001",
        category=STRIDECategory.REPUDIATION,
        title="No Message Origin Audit Trail",
        description="MQTT has no built-in message signing. Agent can deny sending commands.",
        mitigation="Implement HMAC message signing. Log all publish events.",
        severity="MEDIUM",
        cvss_score=5.3,
    ),
    STRIDEThreat(
        threat_id="MAS-I-001",
        category=STRIDECategory.INFO_DISCLOSURE,
        title="Unauthenticated Wildcard Topic Enumeration",
        description="Anonymous subscriber enumerates all topics via wildcard subscription.",
        mitigation="Enable broker authentication. Restrict wildcard subscriptions.",
        severity="HIGH",
        cvss_score=7.2,
    ),
    STRIDEThreat(
        threat_id="MAS-I-002",
        category=STRIDECategory.INFO_DISCLOSURE,
        title="$SYS Topic Exposure — Broker Internals Leaked",
        description="$SYS topics expose broker stats, connected clients, subscriptions.",
        mitigation="Restrict $SYS topic access to authenticated admin clients only.",
        severity="MEDIUM",
        cvss_score=5.8,
    ),
    STRIDEThreat(
        threat_id="MAS-D-001",
        category=STRIDECategory.DENIAL_OF_SERVICE,
        title="Message Flood — Broker Resource Exhaustion",
        description="Attacker publishes at high frequency to exhaust broker memory.",
        mitigation="Enable rate limiting per client_id. Set max_inflight_messages.",
        severity="HIGH",
        cvss_score=7.5,
    ),
    STRIDEThreat(
        threat_id="MAS-E-001",
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        title="ABFP Detected: Topic Privilege Escalation",
        description="Agent publishes to topics outside its behavioral fingerprint baseline.",
        mitigation="Implement topic ACLs. Alert on new publish paths via ABFP.",
        severity="CRITICAL",
        cvss_score=9.3,
    ),
    STRIDEThreat(
        threat_id="MAS-E-002",
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        title="ACL Bypass via Wildcard Misconfiguration",
        description="Broker ACL uses overly broad wildcards allowing unintended access.",
        mitigation="Audit ACL rules. Use explicit topic paths, avoid # at root level.",
        severity="CRITICAL",
        cvss_score=8.8,
    ),
]
