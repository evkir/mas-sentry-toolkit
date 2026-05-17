# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for ABFPFingerprinter Phase 1 & 2.
Run: pytest tests/unit/test_fingerprinter.py -v
"""

from mas_sentry.agents.abfp_models import AgentFingerprint, MessageEvent
from mas_sentry.agents.fingerprinter import ABFPFingerprinter


def make_fp_with_events(n: int, interval_s: float = 1.0, payload_size: int = 48) -> AgentFingerprint:
    """Helper: create AgentFingerprint with n synthetic events"""
    now = 1000.0
    fp = AgentFingerprint(agent_id="test_agent", first_seen=now, last_seen=now + n * interval_s)
    for i in range(n):
        fp.message_events.append(
            MessageEvent(
                topic="sensors/test/telemetry",
                payload_size=payload_size,
                timestamp=now + i * interval_s,
                payload_preview='{"temp": 22.5}',
            )
        )
    return fp


class TestABFPFingerprinter:
    def setup_method(self):
        self.fp_engine = ABFPFingerprinter("127.0.0.1")

    def test_infer_agent_id_two_parts(self):
        agent_id = self.fp_engine._infer_agent_id("sensors/sensor_001/telemetry")
        assert agent_id == "inferred_sensors_sensor_001"

    def test_infer_agent_id_one_part(self):
        agent_id = self.fp_engine._infer_agent_id("status")
        assert agent_id == "inferred_status"

    def test_compute_timing_basic(self):
        fp = make_fp_with_events(10, interval_s=1.0)
        self.fp_engine._compute_timing(fp)
        # Mean interval should be ~1000ms
        assert abs(fp.timing.mean_interval_ms - 1000.0) < 5.0
        assert fp.timing.sample_count == 9

    def test_compute_timing_burst_detection(self):
        fp = make_fp_with_events(10, interval_s=0.01)  # 10ms intervals
        self.fp_engine._compute_timing(fp)
        assert fp.timing.burst_detected is True

    def test_compute_payload_basic(self):
        fp = make_fp_with_events(5, payload_size=64)
        self.fp_engine._compute_payload(fp)
        assert fp.payload.mean_size_bytes == 64.0
        assert fp.payload.min_size_bytes == 64
        assert fp.payload.max_size_bytes == 64

    def test_confidence_low(self):
        fp = make_fp_with_events(3)
        self.fp_engine._compute_confidence(fp)
        assert fp.confidence < 0.5

    def test_confidence_high(self):
        fp = make_fp_with_events(50)
        self.fp_engine._compute_confidence(fp)
        assert fp.confidence == 1.0

    def test_build_fingerprints_pipeline(self):
        fp = make_fp_with_events(20, interval_s=1.0, payload_size=48)
        self.fp_engine.fingerprints["test_agent"] = fp
        result = self.fp_engine.build_fingerprints()
        agent = result["test_agent"]
        assert agent.timing.mean_interval_ms > 0
        assert agent.payload.mean_size_bytes == 48.0
        assert agent.confidence > 0
