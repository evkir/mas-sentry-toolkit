# SPDX-License-Identifier: AGPL-3.0-or-later
"""An unreachable broker, a refused CONNECT and an idle broker are three results."""

from typing import ClassVar

import pytest

import mas_sentry.protocols.mqtt_fingerprint as fp
import mas_sentry.protocols.mqtt_topic_walker as tw
from mas_sentry.protocols.mqtt_connect import (
    BrokerRefusedConnection,
    BrokerUnreachable,
    await_connack,
    reason_code,
    reason_text,
)


class _ReasonCode:
    """Stand-in for paho v2 ReasonCode: compares to int, but int() rejects it."""

    def __init__(self, value: int, text: str):
        self.value = value
        self._text = text

    def __eq__(self, other):
        return self.value == other

    def __str__(self):
        return self._text


def test_await_connack_passes_on_success():
    await_connack({"rc": 0}, timeout=0.1)


def test_await_connack_reports_a_silent_broker_as_unreachable():
    with pytest.raises(BrokerUnreachable):
        await_connack({}, timeout=0.1)


def test_await_connack_carries_the_refusal_reason():
    with pytest.raises(BrokerRefusedConnection) as exc:
        await_connack({"rc": _ReasonCode(135, "Not authorized")}, timeout=0.1)
    assert exc.value.code == 135
    assert "Not authorized" in exc.value.reason


def test_reason_helpers_read_paho_v2_reason_codes():
    """paho v2 hands over a ReasonCode; int() on it raises, `.value` is the code."""
    rc = _ReasonCode(135, "Not authorized")
    with pytest.raises(TypeError):
        int(rc)
    assert reason_code(rc) == 135
    assert reason_text(rc) == "Not authorized"


def test_reason_code_falls_back_when_the_shape_is_unknown():
    assert reason_code(object()) == -1


class _FakeClient:
    """Minimal paho stand-in driving on_connect with a configurable reason."""

    rc: object = 0
    raise_connect = False
    subscribed: ClassVar[list[str]] = []

    def __init__(self, *a, **k):
        self.on_connect = None
        self.on_message = None
        _FakeClient.subscribed = []

    def connect(self, *a, **k):
        if _FakeClient.raise_connect:
            raise OSError("connection refused")

    def loop_start(self):
        if self.on_connect:
            self.on_connect(self, None, None, _FakeClient.rc)

    def subscribe(self, topic, qos=0):
        _FakeClient.subscribed.append(topic)

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture(autouse=True)
def _patch_paho(monkeypatch):
    for mod in (tw, fp):
        monkeypatch.setattr(mod.mqtt, "Client", _FakeClient)
        monkeypatch.setattr(mod.time, "sleep", lambda *_: None)
    _FakeClient.rc = 0
    _FakeClient.raise_connect = False


def test_walker_reports_a_refused_subscription_instead_of_an_empty_tree():
    """The bug this guards: a rejected CONNECT returned [] - same as an idle broker."""
    _FakeClient.rc = _ReasonCode(135, "Not authorized")
    with pytest.raises(BrokerRefusedConnection):
        tw.MQTTTopicWalker("127.0.0.1").walk(duration=0)


def test_walker_raises_unreachable_rather_than_a_raw_socket_error():
    _FakeClient.raise_connect = True
    with pytest.raises(BrokerUnreachable):
        tw.MQTTTopicWalker("127.0.0.1").walk(duration=0)


def test_walker_returns_topics_when_the_broker_accepts():
    walker = tw.MQTTTopicWalker("127.0.0.1")
    walker.discovered = {"factory/robot/telemetry", "factory/sensors/temp"}
    assert walker.walk(duration=0) == ["factory/robot/telemetry", "factory/sensors/temp"]
    assert "#" in _FakeClient.subscribed


def test_fingerprinter_raises_instead_of_returning_an_unreachable_dict():
    _FakeClient.raise_connect = True
    with pytest.raises(BrokerUnreachable):
        fp.MQTTBrokerFingerprinter("127.0.0.1").fingerprint()


def test_fingerprinter_reports_a_refused_connection():
    _FakeClient.rc = _ReasonCode(135, "Not authorized")
    with pytest.raises(BrokerRefusedConnection):
        fp.MQTTBrokerFingerprinter("127.0.0.1").fingerprint()


def test_fingerprinter_identifies_the_broker_from_sys_topics():
    fingerprinter = fp.MQTTBrokerFingerprinter("127.0.0.1")
    fingerprinter.sys_topics = {"$SYS/broker/version": "mosquitto version 2.0.18"}
    result = fingerprinter.fingerprint()
    assert result["broker_type"] == "Eclipse Mosquitto"
    assert "$SYS/#" in _FakeClient.subscribed
