# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for AMQPAnalyzer.
Run: pytest tests/ -v
These tests mock the HTTP API so no real RabbitMQ needed.
"""
import pytest
from unittest.mock import patch, MagicMock
import json

from mas_sentry.protocols.amqp_analyzer import AMQPAnalyzer

MOCK_OVERVIEW = {
    "rabbitmq_version": "3.12.0",
    "management_version": "3.12.0",
    "message_stats": {}
}

MOCK_EXCHANGES = [
    {"name": "", "type": "direct", "durable": True, "auto_delete": False},
    {"name": "amq.topic", "type": "topic", "durable": True, "auto_delete": False},
    {"name": "mas.commands", "type": "direct", "durable": False, "auto_delete": False},
]

MOCK_QUEUES = [
    {"name": "sensor_data", "messages": 42, "consumers": 1, "durable": True},
    {"name": "alerts", "messages": 0, "consumers": 0, "durable": False},
]

class TestAMQPAnalyzer:

    def setup_method(self):
        self.analyzer = AMQPAnalyzer("127.0.0.1", 5672)

    @patch.object(AMQPAnalyzer, "_api_get")
    def test_connect_success(self, mock_api):
        mock_api.return_value = MOCK_OVERVIEW
        result = self.analyzer.connect()
        assert result is True
        assert self.analyzer.is_running is True

    @patch.object(AMQPAnalyzer, "_api_get")
    def test_connect_failure(self, mock_api):
        mock_api.return_value = None
        result = self.analyzer.connect()
        assert result is False

    @patch.object(AMQPAnalyzer, "_api_get")
    def test_enumerate_exchanges(self, mock_api):
        mock_api.return_value = MOCK_EXCHANGES
        exchanges = self.analyzer.enumerate_exchanges()
        assert len(exchanges) == 3
        assert exchanges[2]["name"] == "mas.commands"

    @patch.object(AMQPAnalyzer, "_api_get")
    def test_enumerate_queues(self, mock_api):
        mock_api.return_value = MOCK_QUEUES
        queues = self.analyzer.enumerate_queues()
        assert len(queues) == 2
        assert queues[0]["messages"] == 42

    @patch.object(AMQPAnalyzer, "_api_get")
    def test_default_credentials_detected(self, mock_api):
        mock_api.return_value = MOCK_OVERVIEW
        result = self.analyzer.check_default_credentials()
        assert result is True

    @patch.object(AMQPAnalyzer, "_api_get")
    def test_default_credentials_rejected(self, mock_api):
        mock_api.return_value = None
        result = self.analyzer.check_default_credentials()
        assert result is False
