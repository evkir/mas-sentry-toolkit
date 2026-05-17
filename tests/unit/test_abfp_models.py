# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for ABFP data models.
Run: pytest tests/unit/test_abfp_models.py -v
"""
import pytest
import time
from mas_sentry.agents.abfp_models import (
    MessageEvent, AgentFingerprint, TimingMetrics,
    PayloadMetrics, BehavioralBaseline, TopicProfile
)


class TestMessageEvent:
    def test_to_dict(self):
        ev = MessageEvent(
            topic="sensors/temp",
            payload_size=48,
            timestamp=1000.0,
            qos=1
        )
        d = ev.to_dict()
        assert d["topic"] == "sensors/temp"
        assert d["payload_size"] == 48
        assert d["qos"] == 1


class TestAgentFingerprint:
    def setup_method(self):
        self.fp = AgentFingerprint(
            agent_id="inferred_sensors_sensor_001",
            first_seen=1000.0,
            last_seen=1120.0
        )

    def test_active_duration(self):
        assert self.fp.active_duration_seconds == 120.0

    def test_add_threat_flag(self):
        self.fp.add_threat_flag("NEW_TOPIC_DETECTED")
        self.fp.add_threat_flag("NEW_TOPIC_DETECTED")  # duplicate
        assert len(self.fp.threat_flags) == 1

    def test_to_dict_structure(self):
        d = self.fp.to_dict()
        assert "agent_id" in d
        assert "timing" in d
        assert "payload" in d
        assert "anomaly_score" in d
        assert "threat_flags" in d

    def test_to_json(self):
        import json
        j = self.fp.to_json()
        parsed = json.loads(j)
        assert parsed["agent_id"] == "inferred_sensors_sensor_001"


class TestBehavioralBaseline:
    def test_deviation_new_topics(self):
        baseline = BehavioralBaseline(
            agent_id="sensor",
            known_topics=["sensors/temp"],
            expected_interval_ms=1000.0,
            expected_payload_size=48.0,
            expected_entropy=3.5
        )
        fp = AgentFingerprint(
            agent_id="sensor",
            first_seen=0, last_seen=60
        )
        fp.topic_profiles["sensors/temp"] = TopicProfile("sensors/temp")
        fp.topic_profiles["commands/admin"] = TopicProfile("commands/admin")
        fp.timing.mean_interval_ms = 1000.0
        fp.payload.mean_size_bytes = 48.0
        fp.payload.entropy_score = 3.5

        score = baseline.deviation_score(fp)
        # One new topic = +15 points
        assert score >= 15.0

    def test_deviation_normal(self):
        baseline = BehavioralBaseline(
            agent_id="sensor",
            known_topics=["sensors/temp"],
            expected_interval_ms=1000.0,
            expected_payload_size=48.0,
            expected_entropy=3.5
        )
        fp = AgentFingerprint(
            agent_id="sensor",
            first_seen=0, last_seen=60
        )
        fp.topic_profiles["sensors/temp"] = TopicProfile("sensors/temp")
        fp.timing.mean_interval_ms = 1000.0
        fp.payload.mean_size_bytes = 48.0
        fp.payload.entropy_score = 3.5

        score = baseline.deviation_score(fp)
        assert score < 5.0
