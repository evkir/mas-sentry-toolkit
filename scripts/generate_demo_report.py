#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Demo script: generate a sample MAS-Sentry HTML + JSON report.
Usage: python3 scripts/generate_demo_report.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mas_sentry.reporting.report_model import MASAuditReport, ReportMeta
from mas_sentry.reporting.html_report import HTMLReportGenerator

report = MASAuditReport(
    meta=ReportMeta(
        session_id="demo-001",
        target="127.0.0.1",
        protocol="mqtt"
    )
)

# Protocol findings
report.add_finding(
    "Anonymous Broker Access", "CRITICAL",
    "MQTT broker at 127.0.0.1:1883 accepts anonymous connections. "
    "Any client can subscribe to all topics including command channels.",
    evidence={"port": 1883, "anonymous": True},
    remediation="Enable authentication. Set allow_anonymous false in mosquitto.conf."
)
report.add_finding(
    "$SYS Topic Information Leakage", "MEDIUM",
    "Broker version and client stats exposed via $SYS/# to unauthenticated clients.",
    evidence={"version": "mosquitto 2.0.18", "sys_topics": 47},
    remediation="Restrict $SYS topic access via ACL."
)
report.add_finding(
    "Retained Message Poisoning", "HIGH",
    "Unauthenticated client successfully published retained message to commands/actuator.",
    evidence={"topic": "commands/actuator/cooling", "payload": "FORCE_ON"},
    remediation="Implement publish ACLs. Validate retained message origin."
)

# ABFP fingerprints
report.abfp_fingerprints = [
    {
        "agent_id": "inferred_sensors_sensor_001",
        "message_count": 240,
        "anomaly_score": 0.0,
        "is_rogue": False,
        "threat_flags": [],
        "timing": {"mean_interval_ms": 1001.2},
        "payload": {"encoding": "json", "entropy_score": 3.82},
    },
    {
        "agent_id": "inferred_commands_unknown_agent",
        "message_count": 45,
        "anomaly_score": 85.0,
        "is_rogue": True,
        "threat_flags": ["TOPIC_ESCALATION", "NO_BASELINE", "BURST_DETECTED"],
        "timing": {"mean_interval_ms": 22.4},
        "payload": {"encoding": "binary", "entropy_score": 7.2},
    },
]

# STRIDE threats
from mas_sentry.threat_modeling.stride import MAS_THREAT_CATALOG
report.stride_threats = [
    t.to_dict() for t in MAS_THREAT_CATALOG
    if t.severity in ["CRITICAL", "HIGH"]
]

# Save reports
os.makedirs("reports", exist_ok=True)
report.save_json("reports/demo_report.json")
HTMLReportGenerator(report).save("reports/demo_report.html")

print("\n[+] Open reports/demo_report.html in your browser!")
