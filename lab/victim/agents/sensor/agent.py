import json
import os
import random
import time

import paho.mqtt.client as mqtt

BROKER = os.getenv("BROKER", "127.0.0.1")
AGENT_ID = os.getenv("AGENT_ID", "sensor_001")

client = mqtt.Client(client_id=AGENT_ID)
client.connect(BROKER, 1883, 60)
print(f"[{AGENT_ID}] Connected to broker {BROKER}")

while True:
    payload = json.dumps(
        {
            "agent": AGENT_ID,
            "temp": round(20 + random.uniform(-2, 5), 2),
            "humidity": round(50 + random.uniform(-5, 10), 2),
            "timestamp": time.time(),
        }
    )
    client.publish(f"sensors/{AGENT_ID}/telemetry", payload, qos=1)
    client.publish("sensors/all/status", json.dumps({"online": True, "id": AGENT_ID}))
    print(f"[{AGENT_ID}] Published telemetry")
    time.sleep(1)
