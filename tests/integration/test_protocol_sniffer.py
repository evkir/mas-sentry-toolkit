import time
import json
import pytest
import paho.mqtt.client as mqtt

LAB_BROKER = "127.0.0.1"
LAB_MQTT = 1883
CAPTURE_DURATION = 5

@pytest.fixture(scope="module")
def mqtt_publisher():
    client = mqtt.Client(client_id="test-publisher")
    connected = {"ok": False}
    client.on_connect = lambda c, u, f, rc: connected.update({"ok": rc == 0})
    try:
        client.connect(LAB_BROKER, LAB_MQTT, keepalive=10)
        client.loop_start()
        time.sleep(1)
        if not connected["ok"]:
            pytest.skip("Lab broker not available")
        payloads = [
            ("sensors/test_001/telemetry", json.dumps({"temp": 22.5})),
            ("sensors/all/status", json.dumps({"online": True})),
            ("admin/config", json.dumps({"password": "admin123"})),
        ]
        for topic, payload in payloads:
            client.publish(topic, payload, qos=1)
            time.sleep(0.1)
        yield client
    finally:
        client.loop_stop()
        client.disconnect()

class TestMQTTCapture:

    def test_can_connect_anonymously(self):
        client = mqtt.Client(client_id="test-anon")
        result = {"rc": -1}
        client.on_connect = lambda c, u, f, rc: result.update({"rc": rc})
        try:
            client.connect(LAB_BROKER, LAB_MQTT, keepalive=5)
            client.loop_start()
            time.sleep(1.5)
            client.loop_stop()
            client.disconnect()
        except Exception:
            pytest.skip("Lab broker not reachable")
        assert result["rc"] == 0

    def test_wildcard_captures_messages(self, mqtt_publisher):
        captured = []
        client = mqtt.Client(client_id="test-wildcard")
        client.on_message = lambda c, u, msg: captured.append(msg.topic)
        client.on_connect = lambda c, u, f, rc: c.subscribe("#", qos=0)
        try:
            client.connect(LAB_BROKER, LAB_MQTT)
            client.loop_start()
            time.sleep(CAPTURE_DURATION)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            pytest.skip(f"Not reachable: {e}")
        assert len(captured) > 0
        assert any("sensors" in t for t in captured)
