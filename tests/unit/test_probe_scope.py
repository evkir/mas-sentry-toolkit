# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

from mas_sentry.agents.active_prober import ActiveProber
from mas_sentry.core.scope import ScopeViolation
from mas_sentry.protocols.amqp_analyzer import AMQPAnalyzer
from mas_sentry.protocols.mqtt_analyzer import MQTTAnalyzer
from mas_sentry.protocols.mqtt_auth_check import MQTTAuthChecker
from mas_sentry.protocols.mqtt_fingerprint import MQTTBrokerFingerprinter
from mas_sentry.protocols.mqtt_topic_walker import MQTTTopicWalker

PROBES = [
    ActiveProber,
    AMQPAnalyzer,
    MQTTAnalyzer,
    MQTTAuthChecker,
    MQTTBrokerFingerprinter,
    MQTTTopicWalker,
]


@pytest.mark.parametrize("cls", PROBES)
def test_probe_blocks_public_host(cls):
    with pytest.raises(ScopeViolation):
        cls("api.example.com")


@pytest.mark.parametrize("cls", PROBES)
def test_probe_allows_lab_host(cls):
    cls("127.0.0.1")


@pytest.mark.parametrize("cls", PROBES)
def test_probe_allows_confirmed(cls):
    cls("api.example.com", confirmed=True)
