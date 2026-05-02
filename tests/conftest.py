"""
Shared pytest fixtures for MAS-Sentry test suite.
"""
import pytest
from mas_sentry.reporting.report_model import MASAuditReport, ReportMeta
from mas_sentry.agents.abfp_models import (
    AgentFingerprint, TimingMetrics, PayloadMetrics, TopicProfile
)


@pytest.fixture
def sample_report():
    report = MASAuditReport(
        meta=ReportMeta(
            session_id="fixture-001",
            target="127.0.0.1",
            protocol="mqtt"
        )
    )
    report.add_finding(
        "Anonymous Access", "CRITICAL",
        "Broker allows anonymous connections",
        remediation="Enable authentication"
    )
    return report


@pytest.fixture
def clean_fingerprint():
    fp = AgentFingerprint(
        agent_id="inferred_sensors_sensor_001",
        first_seen=1000.0,
        last_seen=1120.0
    )
    fp.timing = TimingMetrics(
        mean_interval_ms=1000.0,
        std_interval_ms=10.0,
        min_interval_ms=980.0,
        max_interval_ms=1020.0,
        burst_detected=False,
        sample_count=119
    )
    fp.payload = PayloadMetrics(
        mean_size_bytes=48.0,
        std_size_bytes=2.0,
        min_size_bytes=46,
        max_size_bytes=50,
        entropy_score=3.82,
        encoding="json"
    )
    fp.confidence = 1.0
    fp.topic_profiles["sensors/sensor_001/telemetry"] = TopicProfile(
        topic="sensors/sensor_001/telemetry",
        message_count=120
    )
    return fp


@pytest.fixture
def rogue_fingerprint():
    fp = AgentFingerprint(
        agent_id="inferred_commands_unknown",
        first_seen=1000.0,
        last_seen=1045.0
    )
    fp.timing = TimingMetrics(
        mean_interval_ms=22.0,
        std_interval_ms=5.0,
        min_interval_ms=10.0,
        max_interval_ms=50.0,
        burst_detected=True,
        sample_count=44
    )
    fp.payload = PayloadMetrics(
        mean_size_bytes=512.0,
        std_size_bytes=50.0,
        min_size_bytes=400,
        max_size_bytes=600,
        entropy_score=7.2,
        encoding="binary"
    )
    fp.confidence = 0.9
    fp.topic_profiles["commands/admin/reset"] = TopicProfile(
        topic="commands/admin/reset",
        message_count=45
    )
    return fp
