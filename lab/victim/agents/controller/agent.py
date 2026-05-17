import json
import os

import paho.mqtt.client as mqtt

BROKER = os.getenv("BROKER", "127.0.0.1")
AGENT_ID = os.getenv("AGENT_ID", "controller_001")


def on_message(client, userdata, msg):
    data = json.loads(msg.payload)
    print(f"[CONTROLLER] Received on {msg.topic}: {data}")
    if data.get("temp", 0) > 23:
        cmd = json.dumps({"action": "activate_cooling", "from": AGENT_ID})
        client.publish("commands/actuator/cooling", cmd, qos=2)
        print("[CONTROLLER] Sent cooling command")


client = mqtt.Client(client_id=AGENT_ID)
client.on_message = on_message
client.connect(BROKER, 1883, 60)
client.subscribe("sensors/#", qos=1)
client.loop_forever()
