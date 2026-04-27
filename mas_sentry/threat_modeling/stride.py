"""
STRIDE Threat Modeling for Multi-Agent Systems.
Maps ABFP findings and protocol vulnerabilities to STRIDE categories.
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class STRIDECategory(Enum):
    SPOOFING             = "Spoofing"
    TAMPERING            = "Tampering"
    REPUDIATION          = "Repudiation"
    INFO_DISCLOSURE      = "Information Disclosure"
    DENIAL_OF_SERVICE    = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class STRIDEThreat:
    """A single STRIDE-categorized threat for MAS"""
    threat_id: str
    category: STRIDECategory
    title: str
    description: str
    mitigation: str
    severity: str
    affected_protocol: str          # mqtt / amqp / both
    abfp_flag: Optional[str] = None # matching ABFP threat flag
    cve_refs: List[str] = field(default_factory=list)
    cvss_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "threat_id": self.threat_id,
            "category": self.category.value,
            "title": self.title,
            "severity": self.severity,
            "affected_protocol": self.affected_protocol,
            "abfp_flag": self.abfp_flag,
            "cvss_score": self.cvss_score,
            "mitigation": self.mitigation,
        }


MAS_THREAT_CATALOG: List[STRIDEThreat] = [

    # ── SPOOFING ──────────────────────────────────────────────
    STRIDEThreat(
        threat_id="MAS-S-001",
        category=STRIDECategory.SPOOFING,
        title="Agent Identity Spoofing via MQTT Client ID",
        description=(
            "MQTT does not verify client identity by default. "
            "An attacker can connect with any client_id and impersonate "
            "a legitimate agent, receiving commands intended for it."
        ),
        mitigation=(
            "Enforce mutual TLS (mTLS). Validate client certificates. "
            "Use unique per-agent credentials. Enable MQTT ACLs."
        ),
        severity="CRITICAL",
        affected_protocol="mqtt",
        abfp_flag="NO_BASELINE",
        cvss_score=9.1,
    ),
    STRIDEThreat(
        threat_id="MAS-S-002",
        category=STRIDECategory.SPOOFING,
        title="Behavioral Clone — Agent Impersonation",
        description=(
            "Attacker mirrors the behavioral fingerprint of a legitimate agent "
            "(same topics, same timing) to evade detection while injecting "
            "malicious payloads."
        ),
        mitigation=(
            "Use ABFP payload entropy analysis to detect anomalies "
            "even when timing matches. Implement payload signing (HMAC)."
        ),
        severity="CRITICAL",
        affected_protocol="both",
        abfp_flag="HIGH_ENTROPY",
        cvss_score=8.8,
    ),

    # ── TAMPERING ─────────────────────────────────────────────
    STRIDEThreat(
        threat_id="MAS-T-001",
        category=STRIDECategory.TAMPERING,
        title="Retained Message Poisoning",
        description=(
            "Attacker publishes a malicious retained message to a command topic. "
            "All agents that subscribe after the attack receive the poisoned state."
        ),
        mitigation=(
            "Restrict publish ACLs on command topics. "
            "Validate message schema server-side. "
            "Monitor retained messages with ABFP scanner."
        ),
        severity="HIGH",
        affected_protocol="mqtt",
        abfp_flag=None,
        cvss_score=7.5,
    ),
    STRIDEThreat(
        threat_id="MAS-T-002",
        category=STRIDECategory.TAMPERING,
        title="Will Message Hijacking",
        description=(
            "Attacker registers a will message on a sensitive topic and "
            "forces an ungraceful disconnect, triggering unintended state "
            "changes in downstream agents."
        ),
        mitigation=(
            "Restrict will topic permissions. "
            "Validate will payloads against expected schema."
        ),
        severity="HIGH",
        affected_protocol="mqtt",
        cvss_score=7.2,
    ),

    # ── REPUDIATION ───────────────────────────────────────────
    STRIDEThreat(
        threat_id="MAS-R-001",
        category=STRIDECategory.REPUDIATION,
        title="No Message Attribution in MQTT",
        description=(
            "MQTT messages carry no cryptographic signature. "
            "An agent cannot prove it sent (or did not send) a message, "
            "enabling denial of malicious actions."
        ),
        mitigation=(
            "Implement HMAC payload signing. "
            "Log all messages with broker-side timestamps. "
            "Use TLS client certificates for identity attribution."
        ),
        severity="MEDIUM",
        affected_protocol="mqtt",
        cvss_score=5.3,
    ),

    # ── INFORMATION DISCLOSURE ────────────────────────────────
    STRIDEThreat(
        threat_id="MAS-I-001",
        category=STRIDECategory.INFO_DISCLOSURE,
        title="Unauthenticated Topic Enumeration",
        description=(
            "Anonymous subscriber connects and uses wildcard (#) to "
            "receive all broker traffic, including sensor data, "
            "credentials, and internal state."
        ),
        mitigation=(
            "Disable anonymous access. "
            "Restrict wildcard subscriptions. "
            "Enable TLS for all connections."
        ),
        severity="HIGH",
        affected_protocol="mqtt",
        cvss_score=7.5,
    ),
    STRIDEThreat(
        threat_id="MAS-I-002",
        category=STRIDECategory.INFO_DISCLOSURE,
        title="$SYS Topic Information Leakage",
        description=(
            "Mosquitto exposes broker internals (version, client count, "
            "uptime) via $SYS/# topics accessible to anonymous clients. "
            "Used for reconnaissance."
        ),
        mitigation=(
            "Restrict $SYS topic access to admin clients only. "
            "Upgrade broker or use ACL rules."
        ),
        severity="MEDIUM",
        affected_protocol="mqtt",
        cvss_score=5.0,
    ),

    # ── DENIAL OF SERVICE ─────────────────────────────────────
    STRIDEThreat(
        threat_id="MAS-D-001",
        category=STRIDECategory.DENIAL_OF_SERVICE,
        title="MQTT Broker Flood via Burst Publishing",
        description=(
            "Attacker publishes messages at extremely high rate, "
            "exhausting broker memory and causing legitimate agents "
            "to lose connectivity."
        ),
        mitigation=(
            "Configure per-client rate limits on broker. "
            "Use ABFP burst detection to alert on abnormal publish rates."
        ),
        severity="HIGH",
        affected_protocol="mqtt",
        abfp_flag="BURST_DETECTED",
        cvss_score=7.5,
    ),

    # ── ELEVATION OF PRIVILEGE ────────────────────────────────
    STRIDEThreat(
        threat_id="MAS-E-001",
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        title="Topic Privilege Escalation",
        description=(
            "Compromised agent begins publishing to topics outside its "
            "assigned role (e.g., sensor publishes to commands/actuator). "
            "ABFP detects this as topic escalation."
        ),
        mitigation=(
            "Enforce strict topic ACLs per agent role. "
            "Use ABFP TOPIC_ESCALATION flag to detect and alert."
        ),
        severity="CRITICAL",
        affected_protocol="mqtt",
        abfp_flag="TOPIC_ESCALATION",
        cvss_score=9.0,
    ),
    STRIDEThreat(
        threat_id="MAS-E-002",
        category=STRIDECategory.ELEVATION_OF_PRIVILEGE,
        title="RabbitMQ Default Credential Escalation",
        description=(
            "RabbitMQ ships with guest:guest enabled on localhost. "
            "In Docker or misconfigured deployments this is accessible "
            "remotely, giving full broker admin access."
        ),
        mitigation=(
            "Disable guest user. Create role-specific accounts. "
            "Restrict management API to localhost."
        ),
        severity="CRITICAL",
        affected_protocol="amqp",
        cvss_score=9.8,
    ),
]
