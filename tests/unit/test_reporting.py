# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for report generation.
Run: pytest tests/unit/test_reporting.py -v
"""

import json

from mas_sentry.reporting.html_report import HTMLReportGenerator
from mas_sentry.reporting.report_model import MASAuditReport, ReportMeta


def make_report() -> MASAuditReport:
    report = MASAuditReport(meta=ReportMeta(session_id="test1234", target="127.0.0.1", protocol="mqtt"))
    report.add_finding(
        "Anonymous Access",
        "CRITICAL",
        "Broker allows anonymous connections",
        remediation="Enable authentication",
    )
    report.add_finding(
        "$SYS Exposure",
        "MEDIUM",
        "$SYS topics accessible without auth",
        remediation="Add ACL for $SYS topics",
    )
    report.abfp_fingerprints = [
        {
            "agent_id": "inferred_sensors_001",
            "message_count": 120,
            "anomaly_score": 85.0,
            "is_rogue": True,
            "threat_flags": ["TOPIC_ESCALATION"],
            "timing": {"mean_interval_ms": 1000},
            "payload": {"encoding": "json"},
        }
    ]
    report.stride_threats = [
        {
            "threat_id": "MAS-E-001",
            "severity": "CRITICAL",
            "category": "Elevation of Privilege",
            "title": "Topic Privilege Escalation",
            "cvss_score": 9.0,
            "mitigation": "Enforce ACLs",
        }
    ]
    return report


class TestMASAuditReport:
    def test_add_finding(self):
        report = make_report()
        assert len(report.protocol_findings) == 2

    def test_compute_statistics(self):
        report = make_report()
        report.compute_statistics()
        s = report.statistics
        assert s["total_findings"] >= 2
        assert s["agents_analyzed"] == 1
        assert s["rogue_agents"] == 1
        assert s["max_anomaly_score"] == 85.0
        assert s["stride_threats_mapped"] == 1

    def test_json_export_structure(self):
        report = make_report()
        data = json.loads(report.to_json())
        assert "meta" in data
        assert "statistics" in data
        assert "protocol_findings" in data
        assert "abfp_fingerprints" in data
        assert "stride_threats" in data

    def test_json_meta_fields(self):
        report = make_report()
        data = json.loads(report.to_json())
        assert data["meta"]["session_id"] == "test1234"
        assert data["meta"]["target"] == "127.0.0.1"

    def test_severity_breakdown(self):
        report = make_report()
        report.compute_statistics()
        breakdown = report.statistics["severity_breakdown"]
        assert breakdown["CRITICAL"] >= 1
        assert breakdown["MEDIUM"] >= 1


class TestHTMLReportGenerator:
    def test_generates_html(self):
        report = make_report()
        gen = HTMLReportGenerator(report)
        html = gen.generate()
        assert "<!DOCTYPE html>" in html
        assert "MAS-Sentry" in html

    def test_session_id_in_html(self):
        report = make_report()
        gen = HTMLReportGenerator(report)
        html = gen.generate()
        assert "test1234" in html

    def test_findings_in_html(self):
        report = make_report()
        gen = HTMLReportGenerator(report)
        html = gen.generate()
        assert "Anonymous Access" in html
        assert "CRITICAL" in html

    def test_abfp_in_html(self):
        report = make_report()
        gen = HTMLReportGenerator(report)
        html = gen.generate()
        assert "inferred_sensors_001" in html
        assert "85" in html

    def test_stride_in_html(self):
        report = make_report()
        gen = HTMLReportGenerator(report)
        html = gen.generate()
        assert "MAS-E-001" in html
        assert "Privilege Escalation" in html
