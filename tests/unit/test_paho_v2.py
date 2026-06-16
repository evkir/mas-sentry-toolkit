# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression guard for the paho-mqtt v2 callback API migration."""

import warnings

from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.reasoncodes import ReasonCode

from mas_sentry.protocols.mqtt_analyzer import MQTTAnalyzer


def test_analyzer_constructs_without_deprecation_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        MQTTAnalyzer("127.0.0.1")


def test_on_connect_accepts_v2_reason_code_success():
    a = MQTTAnalyzer("127.0.0.1")
    a._on_connect(a.client, None, None, ReasonCode(PacketTypes.CONNACK), None)
    assert a.is_running is True


def test_on_connect_failure_reason_code():
    a = MQTTAnalyzer("127.0.0.1")
    a._on_connect(a.client, None, None, ReasonCode(PacketTypes.CONNACK, "Not authorized"), None)
    assert a.is_running is False


def test_on_disconnect_v2_signature():
    a = MQTTAnalyzer("127.0.0.1")
    a.is_running = True
    a._on_disconnect(a.client, None, None, ReasonCode(PacketTypes.DISCONNECT), None)
    assert a.is_running is False
