# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Integration tests for MQTT protocol sniffer.
Requires running Docker lab: docker-compose up -d
Skipped automatically if broker unavailable.
"""
import pytest
import socket
import paho.mqtt.client as mqtt
import time

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883


def broker_available() -> bool:
    try:
        s = socket.create_connection((BROKER_HOST, BROKER_PORT), timeout=2)
        s.close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.integration
skip_no_broker = pytest.mark.skipif(
    not broker_available(),
    reason="MQTT broker not available - run: docker-compose up -d"
)


@skip_no_broker
class TestMQTTCapture:

    def test_can_connect_anonymously(self):
        connected = {"ok": False}
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                             client_id="test-anon")
        def on_connect(c, u, f, rc, p=None):
            connected["ok"] = (rc == 0)
        client.on_connect = on_connect
        client.connect(BROKER_HOST, BROKER_PORT, keepalive=5)
        client.loop_start()
        time.sleep(2)
        client.loop_stop()
        client.disconnect()
        assert connected["ok"] is True

    def test_wildcard_captures_messages(self):
        received = []
        pub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                          client_id="test-publisher")
        sub = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2,
                          client_id="test-subscriber")
        sub.on_message = lambda c, u, msg: received.append(msg.topic)
        sub.on_connect = lambda c, u, f, rc, p=None: c.subscribe("#")
        sub.connect(BROKER_HOST, BROKER_PORT)
        sub.loop_start()
        time.sleep(1)
        pub.connect(BROKER_HOST, BROKER_PORT)
        pub.loop_start()
        pub.publish("test/integration/ping", "hello", qos=1)
        time.sleep(2)
        sub.loop_stop()
        pub.loop_stop()
        sub.disconnect()
        pub.disconnect()
        assert len(received) > 0
