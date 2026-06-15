# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest

import mas_sentry.protocols.mqtt_auth_check as ac
from mas_sentry.protocols.mqtt_auth_check import BrokerUnreachable, MQTTAuthChecker


class _FakeClient:
    rc = 0
    raise_connect = False

    def __init__(self, *a, **k):
        self.on_connect = None

    def username_pw_set(self, *a, **k):
        pass

    def connect(self, *a, **k):
        if _FakeClient.raise_connect:
            raise OSError("connection refused")

    def loop_start(self):
        if self.on_connect:
            self.on_connect(self, None, None, _FakeClient.rc)

    def loop_stop(self):
        pass

    def disconnect(self):
        pass


@pytest.fixture(autouse=True)
def _patch_paho(monkeypatch):
    monkeypatch.setattr(ac.mqtt, "Client", _FakeClient)
    monkeypatch.setattr(ac.time, "sleep", lambda *_: None)
    _FakeClient.rc = 0
    _FakeClient.raise_connect = False


def test_auth_accepted_returns_true():
    _FakeClient.rc = 0
    assert MQTTAuthChecker("127.0.0.1")._try_connect(label="anon") is True


def test_auth_rejected_returns_false():
    _FakeClient.rc = 5  # not authorized
    assert MQTTAuthChecker("127.0.0.1")._try_connect("u", "p", label="x") is False


def test_unreachable_raises_distinct_error():
    _FakeClient.raise_connect = True
    with pytest.raises(BrokerUnreachable):
        MQTTAuthChecker("127.0.0.1")._try_connect(label="anon")


def test_run_all_handles_unreachable_without_false_security():
    _FakeClient.raise_connect = True
    results = MQTTAuthChecker("127.0.0.1").run_all()
    assert "anonymous_access" not in results
