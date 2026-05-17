# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Integration test: full ABFP + STRIDE + Report pipeline.
No network required — uses synthetic data end-to-end.
Run: pytest tests/integration/ -v -m integration
"""

import json

import pytest

from mas_sentry.agents.abfp_models import BehavioralBaseline
from mas_sentry.agents.anomaly_detector import AnomalyDetector
from mas_sentry.reporting.html_report import HTMLReportGenerator
from mas_sentry.reporting.report_model import MASAuditReport, ReportMeta
from mas_sentry.threat_modeling.stride_mapper import STRIDEMapper

pytestmark = pytest.mark.integration


@pytest.fixture
def pipeline_fingerprints(clean_fingerprint, rogue_fingerprint):
    """Two agents: one clean, one rogue"""
    return {
        clean_fingerprint.agent_id: clean_fingerprint,
        rogue_fingerprint.agent_id: rogue_fingerprint,
    }


@pytest.fixture
def pipeline_baseline(clean_fingerprint):
    return {
        clean_fingerprint.agent_id: BehavioralBaseline(
            agent_id=clean_fingerprint.agent_id,
            known_topics=clean_fingerprint.unique_topics,
            expected_interval_ms=1000.0,
            expected_payload_size=48.0,
            expected_entropy=3.82,
        )
    }


class TestFullPipeline:
    def test_anomaly_detection_on_rogue(self, pipeline_fingerprints, pipeline_baseline):
        detector = AnomalyDetector(pipeline_baseline)
        result = detector.analyze(pipeline_fingerprints)

        clean_id = "inferred_sensors_sensor_001"
        rogue_id = "inferred_commands_unknown"

        assert result[clean_id].anomaly_score < 20.0
        assert result[rogue_id].anomaly_score >= 30.0
        assert result[rogue_id].is_rogue or len(result[rogue_id].threat_flags) > 0

    def test_stride_mapping_from_anomalies(self, pipeline_fingerprints, pipeline_baseline):
        detector = AnomalyDetector(pipeline_baseline)
        result = detector.analyze(pipeline_fingerprints)

        mapper = STRIDEMapper()
        threats = mapper.map_from_fingerprints(result)
        assert len(threats) >= 1
        threat_ids = [t.threat_id for t in threats]
        # Rogue agent → NO_BASELINE → MAS-S-001
        assert any(t.startswith("MAS-") for t in threat_ids)

    def test_report_generation_end_to_end(self, pipeline_fingerprints, pipeline_baseline):
        # Run detector
        detector = AnomalyDetector(pipeline_baseline)
        result = detector.analyze(pipeline_fingerprints)

        # Map STRIDE
        mapper = STRIDEMapper()
        threats = mapper.map_from_fingerprints(result)

        # Build report
        report = MASAuditReport(meta=ReportMeta(session_id="integration-001", target="127.0.0.1", protocol="mqtt"))
        report.add_finding(
            "Anonymous Access",
            "CRITICAL",
            "Broker allows anonymous connections",
            remediation="Enable auth",
        )
        report.abfp_fingerprints = [fp.to_dict() for fp in result.values()]
        report.stride_threats = [t.to_dict() for t in threats]
        report.compute_statistics()

        assert report.statistics["agents_analyzed"] == 2
        assert report.statistics["total_findings"] >= 1
        assert report.statistics["stride_threats_mapped"] >= 1

    def test_json_report_is_valid(self, pipeline_fingerprints, pipeline_baseline):
        detector = AnomalyDetector(pipeline_baseline)
        result = detector.analyze(pipeline_fingerprints)

        report = MASAuditReport(meta=ReportMeta(session_id="json-test-001", target="127.0.0.1", protocol="mqtt"))
        report.abfp_fingerprints = [fp.to_dict() for fp in result.values()]

        parsed = json.loads(report.to_json())
        assert parsed["meta"]["session_id"] == "json-test-001"
        assert len(parsed["abfp_fingerprints"]) == 2

    def test_html_report_contains_all_sections(self, pipeline_fingerprints, pipeline_baseline):
        detector = AnomalyDetector(pipeline_baseline)
        result = detector.analyze(pipeline_fingerprints)

        report = MASAuditReport(meta=ReportMeta(session_id="html-test-001", target="127.0.0.1", protocol="mqtt"))
        report.abfp_fingerprints = [fp.to_dict() for fp in result.values()]
        report.add_finding("Test", "HIGH", "Test finding", remediation="Fix it")

        html = HTMLReportGenerator(report).generate()
        assert "Executive Summary" in html
        assert "ABFP" in html
        assert "inferred_sensors" in html
