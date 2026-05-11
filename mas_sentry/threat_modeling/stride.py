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
    category: STRIDECategory
    title: str
    description: str
    mitigation: str
    severity: str
    cve_refs: Optional[List[str]] = field(default_factory=list)


MAS_MQTT_THREATS = [
    STRIDEThreat(
        category=STRIDECategory.SPOOFING,
        title="Agent Impersonation via MQTT Client ID Spoofing",
        description="MQTT does not natively verify client identity. "
                    "An attacker can set any client_id and impersonate a legitimate agent.",
        mitigation="Implement mutual TLS authentication. "
                   "Validate client certificates against known agent identities.",
        severity="CRITICAL",
    ),
    STRIDEThreat(
        category=STRIDECategory.TAMPERING,
        title="Retained Message Poisoning",
        description="Attacker publishes malicious retained message to a command topic. "
                    "All new subscribers receive the poisoned state.",
        mitigation="Restrict publish permissions to command topics. "
                   "Validate message schema and origin.",
        severity="HIGH",
    ),
    STRIDEThreat(
        category=STRIDECategory.INFO_DISCLOSURE,
        title="Unauthenticated Topic Enumeration",
        description="Anonymous subscriber connects and enumerates all topics "
                    "via wildcard subscription.",
        mitigation="Enable broker authentication. "
                   "Restrict wildcard subscriptions for untrusted clients.",
        severity="HIGH",
    ),
    STRIDEThreat(
        category=STRIDECategory.DENIAL_OF_SERVICE,
        title="Message Flood — Broker Resource Exhaustion",
        description="Attacker publishes at high frequency to exhaust broker memory "
                    "and disconnect legitimate agents.",
        mitigation="Enable rate limiting per client_id. "
                   "Set max_inflight_messages and max_queued_messages on broker.",
        severity="HIGH",
    ),
    STRIDEThreat(
        category=STRIDECategory.REPUDIATION,
        title="No Message Origin Audit Trail",
        description="MQTT has no built-in message signing. "
                    "An agent can deny sending a command with no way to prove otherwise.",
        mitigation="Implement message signing with HMAC or asymmetric keys. "
                   "Log all publish events with client_id and timestamp.",
        severity="MEDIUM",
    ),
    STRIDEThreat(
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        title="ABFP Detected: Topic Privilege Escalation",
        description="Agent begins publishing to topics outside its behavioral fingerprint baseline. "
                    "Indicates compromised agent or attacker with stolen credentials.",
        mitigation="Implement topic ACLs. "
                   "Use ABFP anomaly detection to alert on new publish paths.",
        severity="CRITICAL",
    ),
]
