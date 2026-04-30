"""
lab/scenarios/insecure_command_topic.py
Vulnerable scenario: insecure command topic with no auth/validation.
DAY 13 — Commit 3
"""

import paho.mqtt.client as mqtt
import json
import time
import os

BROKER = os.getenv("BROKER", "127.0.0.1")
AGENT_ID = os.getenv("AGENT_ID", "vulnerable_actuator_001")

COMMAND_TOPIC = "commands/actuator/#"
STATUS_TOPIC = f"status/{AGENT_ID}"


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[{AGENT_ID}] Connected to broker")
        client.subscribe(COMMAND_TOPIC, qos=1)
        print(f"[{AGENT_ID}] Subscribed to {COMMAND_TOPIC}")
    else:
        print(f"[{AGENT_ID}] Connect failed rc={rc}")


def on_message(client, userdata, msg):
    """
    VULNERABILITY: no authentication, no schema validation.
    Executes ANY command received on the topic.
    """
    try:
        data = json.loads(msg.payload)
    except Exception:
        print(f"[{AGENT_ID}] Invalid JSON on {msg.topic}")
        return

    action = data.get("action", "unknown")
    sender = data.get("from", "unknown")

    print(f"[{AGENT_ID}] Command received from '{sender}': {action}")

    # Simulate executing command with no validation
    if action == "activate_cooling":
        print(f"[{AGENT_ID}] >>> Activating cooling system")
    elif action == "shutdown":
        print(f"[{AGENT_ID}] >>> SHUTDOWN triggered by '{sender}' — UNSAFE!")
    elif action == "update_config":
        new_broker = data.get("broker", "unknown")
        print(f"[{AGENT_ID}] >>> Config override! New broker: {new_broker} — UNSAFE!")
    else:
        print(f"[{AGENT_ID}] >>> Unknown action: {action}")

    # Publish status back
    status = json.dumps({
        "agent": AGENT_ID,
        "last_command": action,
        "from": sender,
        "timestamp": time.time()
    })
    client.publish(STATUS_TOPIC, status, qos=1)


client = mqtt.Client(client_id=AGENT_ID)
client.on_connect = on_connect
client.on_message = on_message

print(f"[{AGENT_ID}] Starting vulnerable actuator...")
client.connect(BROKER, 1883, keepalive=60)
client.loop_forever()
