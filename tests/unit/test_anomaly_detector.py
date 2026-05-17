# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for ABFP AnomalyDetector.
Run: pytest tests/unit/test_anomaly_detector.py -v
"""
import pytest
from mas_sentry.agents.anomaly_detector import AnomalyDetector
from mas_sentry.agents.abfp_models import (
    AgentFingerprint, BehavioralBaseline,
    TimingMetrics, PayloadMetrics, TopicProfile
)


def make_fp(agent_id="test_agent", messages=20,
            interval_ms=1000.0, payload_size=48.0,
            entropy=3.5, burst=False,
            topics=None) -> AgentFingerprint:
    fp = AgentFingerprint(
        agent_id=agent_id,
        first_seen=0.0,
        last_seen=float(messages)
    )
    fp.timing = TimingMetrics(
        mean_interval_ms=interval_ms,
        std_interval_ms=10.0,
        min_interval_ms=10.0 if burst else interval_ms * 0.9,
        max_interval_ms=interval_ms * 1.1,
        burst_detected=burst,
        sample_count=messages - 1
    )
    fp.payload = PayloadMetrics(
        mean_size_bytes=payload_size,
        std_size_bytes=2.0,
        min_size_bytes=int(payload_size),
        max_size_bytes=int(payload_size),
        entropy_score=entropy,
        encoding="json"
    )
    fp.confidence = 0.9
    for t in (topics or ["sensors/test/telemetry"]):
        fp.topic_profiles[t] = TopicProfile(t, message_count=messages)
    return fp


def make_baseline(agent_id="test_agent",
                  topics=None,
                  interval_ms=1000.0,
                  payload_size=48.0,
                  entropy=3.5) -> BehavioralBaseline:
    return BehavioralBaseline(
        agent_id=agent_id,
        known_topics=topics or ["sensors/test/telemetry"],
        expected_interval_ms=interval_ms,
        expected_payload_size=payload_size,
        expected_entropy=entropy
    )


class TestAnomalyDetector:

    def test_no_anomaly_clean_agent(self):
        baseline = make_baseline()
        detector = AnomalyDetector({"test_agent": baseline})
        fp = make_fp()
        result = detector.analyze({"test_agent": fp})
        assert result["test_agent"].anomaly_score < 15.0
        assert "TIMING_DEVIATION" not in fp.threat_flags

    def test_burst_detection(self):
        detector = AnomalyDetector()
        fp = make_fp(burst=True)
        detector.analyze({"test_agent": fp})
        assert "BURST_DETECTED" in fp.threat_flags
        assert fp.anomaly_score >= 20.0

    def test_topic_escalation(self):
        baseline = make_baseline(topics=["sensors/test/telemetry"])
        detector = AnomalyDetector({"test_agent": baseline})
        fp = make_fp(topics=["sensors/test/telemetry", "commands/admin/reset"])
        detector.analyze({"test_agent": fp})
        assert "TOPIC_ESCALATION" in fp.threat_flags
        assert fp.anomaly_score >= 15.0

    def test_high_entropy_flag(self):
        detector = AnomalyDetector()
        fp = make_fp(entropy=7.5)
        detector.analyze({"test_agent": fp})
        assert "HIGH_ENTROPY" in fp.threat_flags

    def test_no_baseline_flag(self):
        detector = AnomalyDetector()   # no baselines
        fp = make_fp()
        detector.analyze({"test_agent": fp})
        assert "NO_BASELINE" in fp.threat_flags

    def test_rogue_flag_high_score(self):
        detector = AnomalyDetector()
        fp = make_fp(burst=True, entropy=7.5,
                     topics=["sensors/test", "commands/admin"])
        detector.analyze({"test_agent": fp})
        assert fp.anomaly_score >= 30.0

    def test_json_export(self):
        import json
        detector = AnomalyDetector()
        fp = make_fp(burst=True)
        detector.analyze({"test_agent": fp})
        output = json.loads(detector.to_json())
        assert isinstance(output, list)
        assert len(output) > 0
        assert "finding_type" in output[0]
