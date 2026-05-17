import json
import os
import time

import paho.mqtt.client as mqtt

BROKER = os.getenv("BROKER", "127.0.0.1")
AGENT_ID = os.getenv("AGENT_ID", "logger_001")


def on_message(client, userdata, msg):
    entry = {
        "topic": msg.topic,
        "payload": msg.payload.decode(),
        "qos": msg.qos,
        "time": time.time(),
    }
    print(f"[LOGGER] {json.dumps(entry)}")


client = mqtt.Client(client_id=AGENT_ID)
client.on_message = on_message
client.connect(BROKER, 1883, 60)
client.subscribe("#", qos=0)
client.loop_forever()
