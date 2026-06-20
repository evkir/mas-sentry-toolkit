# SPDX-License-Identifier: AGPL-3.0-or-later
"""ABFP against a real Mosquitto broker. Auto-skips if broker is absent.

Local run:
    docker compose up -d mosquitto
    pytest tests/integration/test_mqtt_lab.py
"""

from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def broker_ready():
    if not _port_open("127.0.0.1", 1883):
        pytest.skip("Mosquitto on 127.0.0.1:1883 not available")
    yield "127.0.0.1:1883"


def test_abfp_scan_runs_against_real_broker(broker_ready, tmp_path: Path):
    import paho.mqtt.client as mqtt

    from mas_sentry.agents.abfp.runtime import run_abfp_scan

    pub = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    pub.connect("127.0.0.1", 1883)
    pub.loop_start()
    for i in range(20):
        pub.publish("factory/robot/r1/state", json.dumps({"i": i}))
        time.sleep(0.05)
    pub.loop_stop()
    pub.disconnect()

    out = tmp_path / "abfp.json"
    result = run_abfp_scan("mqtt://127.0.0.1:1883", duration=3, baseline_threshold=5, out_path=out)
    assert out.exists()
    json.loads(out.read_text())
    assert isinstance(result.findings, list)
    assert isinstance(result.metrics, dict)
