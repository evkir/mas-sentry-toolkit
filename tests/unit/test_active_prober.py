# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for ActiveProber (no network required).
Run: pytest tests/unit/test_active_prober.py -v
"""
import pytest
import json
import time
from unittest.mock import patch, MagicMock
from mas_sentry.agents.active_prober import ActiveProber, ProbeResult


class TestProbeResult:
    def test_to_dict(self):
        r = ProbeResult(
            probe_id="abc123",
            topic="commands/test",
            payload='{"action":"test"}',
            sent_at=1000.0,
            response_topic="sensors/reply",
            response_time_ms=45.2,
            triggered_action=True
        )
        d = r.to_dict()
        assert d["probe_id"] == "abc123"
        assert d["triggered_action"] is True
        assert d["response_time_ms"] == 45.2

    def test_no_response(self):
        r = ProbeResult(
            probe_id="xyz",
            topic="test/topic",
            payload="hello",
            sent_at=1000.0
        )
        assert r.triggered_action is False
        assert r.response_topic is None


class TestActiveProber:

    def setup_method(self):
        self.prober = ActiveProber("127.0.0.1", 1883)

    def test_probe_result_appended(self):
        result = ProbeResult(
            probe_id="test001",
            topic="test/probe",
            payload="test",
            sent_at=time.time(),
            triggered_action=False
        )
        self.prober.results.append(result)
        assert len(self.prober.results) == 1

    def test_command_injection_filters_topics(self):
        non_command_topics = ["sensors/temp", "logs/all"]
        with patch.object(self.prober, "probe_topic") as mock_probe:
            self.prober.probe_command_injection(non_command_topics)
            mock_probe.assert_not_called()

    def test_command_injection_targets_command_topics(self):
        command_topics = ["commands/actuator", "sensors/temp"]
        with patch.object(self.prober, "probe_topic") as mock_probe:
            mock_probe.return_value = ProbeResult(
                "id", "commands/actuator", "{}", time.time()
            )
            self.prober.probe_command_injection(command_topics)
            assert mock_probe.call_count >= 1
            called_topic = mock_probe.call_args[0][0]
            assert "command" in called_topic

    def test_json_export_empty(self):
        output = json.loads(self.prober.to_json())
        assert output == []

    def test_json_export_with_results(self):
        self.prober.results.append(ProbeResult(
            "p1", "test/topic", "payload",
            time.time(), triggered_action=True,
            response_topic="reply/topic", response_time_ms=22.5
        ))
        output = json.loads(self.prober.to_json())
        assert len(output) == 1
        assert output[0]["triggered_action"] is True
