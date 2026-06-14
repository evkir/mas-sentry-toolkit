# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ABFP Phase 3 — Active Probing Engine.
Sends crafted messages to discovered agents and measures
behavioral deviation from established fingerprints.
"""

import json
import time
import uuid
from dataclasses import dataclass

import paho.mqtt.client as mqtt
from rich.console import Console
from rich.table import Table

from mas_sentry.core.scope import assert_in_scope

console = Console()


@dataclass
class ProbeResult:
    probe_id: str
    topic: str
    payload: str
    sent_at: float
    response_topic: str | None = None
    response_payload: str | None = None
    response_time_ms: float | None = None
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

    def __init__(self, host: str, port: int = 1883, confirmed: bool = False):
        assert_in_scope(host, confirmed=confirmed)
        self.host = host
        self.port = port
        self.results: list[ProbeResult] = []
        self._responses: list[dict] = []

    def _make_client(self, client_id: str | None = None) -> mqtt.Client:
        cid = client_id or f"mas-probe-{uuid.uuid4().hex[:6]}"
        c = mqtt.Client(client_id=cid)
        return c

    def probe_topic(self, topic: str, payload: str, listen_topic: str = "#", wait_seconds: float = 3.0) -> ProbeResult:
        """Send a probe message and listen for reactions"""
        result = ProbeResult(probe_id=uuid.uuid4().hex[:8], topic=topic, payload=payload, sent_at=time.time())
        responses = []
        pub = self._make_client("mas-probe-pub")
        sub = self._make_client("mas-probe-sub")

        def on_message(c, u, msg):
            if msg.topic != topic:
                responses.append(
                    {
                        "topic": msg.topic,
                        "payload": msg.payload.decode(errors="replace"),
                        "time": time.time(),
                    }
                )

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
            console.print(f"[bold red][PROBE] Reaction detected! {topic} → {first['topic']}[/bold red]")
        else:
            console.print(f"[green][PROBE] No reaction to probe on '{topic}'[/green]")

        self.results.append(result)
        return result

    def probe_command_injection(self, topics: list[str]) -> list[ProbeResult]:
        """Test if command topics trigger agent reactions"""
        console.print("[bold yellow][PROBE] Command injection probing...[/bold yellow]")
        payloads = [
            '{"action": "shutdown"}',
            '{"action": "restart"}',
            '{"action": "activate_cooling"}',
            '{"cmd": "exec", "args": "id"}',
        ]
        results = []
        for topic in topics:
            if any(kw in topic for kw in ["command", "cmd", "control", "actuator"]):
                for payload in payloads[:2]:
                    r = self.probe_topic(topic, payload, wait_seconds=2.0)
                    results.append(r)
        return results

    def probe_retained_state(self, topics: list[str]) -> list[ProbeResult]:
        """Probe retained message state on discovered topics"""
        console.print("[bold yellow][PROBE] Retained state probing...[/bold yellow]")
        results = []
        poison_payload = json.dumps({"probe": True, "from": "mas-sentry-probe", "action": "test_retained"})
        for topic in topics[:3]:
            r = self.probe_topic(topic, poison_payload, wait_seconds=1.5)
            results.append(r)
        return results

    def probe_hidden_subscribers(self, topics: list[str]) -> dict[str, bool]:
        """Detect hidden subscribers by sending probe and watching for reactions"""
        console.print("[bold yellow][PROBE] Hidden subscriber detection...[/bold yellow]")
        hidden: dict[str, bool] = {}
        for topic in topics:
            r = self.probe_topic(
                topic,
                json.dumps({"probe": "hidden_sub_test", "id": uuid.uuid4().hex[:6]}),
                wait_seconds=2.0,
            )
            hidden[topic] = r.triggered_action
        return hidden

    def print_results(self):
        """Print probe results table"""
        if not self.results:
            console.print("[green][PROBE] No probe results[/green]")
            return
        table = Table(title="[bold red]Active Probe Results[/bold red]")
        table.add_column("Probe ID", style="dim")
        table.add_column("Topic Probed", style="cyan")
        table.add_column("Reaction", style="bold")
        table.add_column("Response Topic", style="yellow")
        table.add_column("RTT ms", justify="right")

        for r in self.results:
            reaction = "[red]YES[/red]" if r.triggered_action else "[green]none[/green]"
            rtt = f"{r.response_time_ms:.0f}" if r.response_time_ms else "—"
            table.add_row(r.probe_id, r.topic[:35], reaction, (r.response_topic or "—")[:30], rtt)
        console.print(table)

    def to_json(self) -> str:
        return json.dumps([r.to_dict() for r in self.results], indent=2)
