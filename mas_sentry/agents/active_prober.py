"""
ABFP Phase 3 — Active Probing Engine.
Sends crafted messages to discovered agents and measures
behavioral deviation from established fingerprints.
"""
import paho.mqtt.client as mqtt
import time
import json
import uuid
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class ProbeResult:
    probe_id: str
    topic: str
    payload: str
    sent_at: float
    response_topic: Optional[str] = None
    response_payload: Optional[str] = None
    response_time_ms: Optional[float] = None
    triggered_action: bool = False

    def to_dict(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "topic": self.topic,
            "payload": self.payload[:40],
            "response_topic": self.response_topic,
            "response_time_ms": self.response_time_ms,
            "triggered_action": self.triggered_action,
        }


class ActiveProber:
    """
    ABFP Phase 3: Active probing.
    Injects crafted MQTT messages and observes agent reactions.
    Detects: command injection, state manipulation, hidden subscribers.
    """

    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port
        self.results: List[ProbeResult] = []
        self._responses: List[dict] = []

    def _make_client(self, client_id: str = None) -> mqtt.Client:
        cid = client_id or f"mas-probe-{uuid.uuid4().hex[:6]}"
        c = mqtt.Client(client_id=cid)
        return c

    def probe_topic(self, topic: str, payload: str,
                    listen_topic: str = "#",
                    wait_seconds: float = 3.0) -> ProbeResult:
        """Send a probe message and listen for reactions"""
        result = ProbeResult(
            probe_id=uuid.uuid4().hex[:8],
            topic=topic,
            payload=payload,
            sent_at=time.time()
        )
        responses = []
        pub = self._make_client("mas-probe-pub")
        sub = self._make_client("mas-probe-sub")

        def on_message(c, u, msg):
            if msg.topic != topic:
                responses.append({
                    "topic": msg.topic,
                    "payload": msg.payload.decode(errors="replace"),
                    "time": time.time()
                })

        sub.on_message = on_message
        sub.on_connect = lambda c, u, f, rc: c.subscribe(listen_topic, qos=0)

        try:
            sub.connect(self.host, self.port)
            sub.loop_start()
            time.sleep(0.5)

            pub.connect(self.host, self.port)
            pub.loop_start()
            pub.publish(topic, payload, qos=1)
            time.sleep(wait_seconds)

            sub.loop_stop()
            pub.loop_stop()
            sub.disconnect()
            pub.disconnect()
        except Exception as e:
            console.print(f"[red][PROBE] Error: {e}[/red]")
            return result

        if responses:
            first = responses[0]
            result.response_topic = first["topic"]
            result.response_payload = first["payload"]
            result.response_time_ms = (first["time"] - result.sent_at) * 1000
            result.triggered_action = True
            console.print(
                f"[bold red][PROBE] Reaction detected! "
                f"{topic} → {first['topic']}[/bold red]"
            )
        else:
            console.print(f"[green][PROBE] No reaction to probe on '{topic}'[/green]")

        self.results.append(result)
        return result
