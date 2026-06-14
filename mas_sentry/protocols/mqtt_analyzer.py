# SPDX-License-Identifier: AGPL-3.0-or-later
import time
from datetime import UTC, datetime

import paho.mqtt.client as mqtt
from rich.console import Console
from rich.table import Table

from .base import BaseProtocolAnalyzer, CapturedMessage

console = Console()


class MQTTAnalyzer(BaseProtocolAnalyzer):
    def __init__(
        self,
        host: str,
        port: int = 1883,
        username: str | None = None,
        password: str | None = None,
        confirmed: bool = False,
    ):
        super().__init__(host, port, confirmed=confirmed)
        self.username = username
        self.password = password
        self.client = mqtt.Client(client_id="mas-sentry-analyzer")
        self.topics_seen: set[str] = set()
        self._setup_callbacks()

    def _setup_callbacks(self):
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.on_disconnect = self._on_disconnect

    def _on_connect(self, client, userdata, flags, rc):
        codes = {
            0: "Connected",
            1: "Bad protocol",
            2: "Client ID rejected",
            3: "Server unavailable",
            4: "Bad credentials",
            5: "Not authorized",
        }
        status = codes.get(rc, f"Unknown ({rc})")
        if rc == 0:
            console.print(f"[bold green][MQTT] {status} to {self.host}:{self.port}[/bold green]")
            self.is_running = True
        else:
            console.print(f"[bold red][MQTT] Connection failed: {status}[/bold red]")

    def _on_message(self, client, userdata, msg):
        captured = CapturedMessage(topic=msg.topic, payload=msg.payload, qos=msg.qos, timestamp=datetime.now(UTC))
        self.messages.append(captured)
        self.topics_seen.add(msg.topic)

    def _on_disconnect(self, client, userdata, rc):
        self.is_running = False

    def connect(self) -> bool:
        if self.username:
            self.client.username_pw_set(self.username, self.password)
        try:
            self.client.connect(self.host, self.port, keepalive=60)
            return True
        except Exception as e:
            console.print(f"[red]Connection error: {e}[/red]")
            return False

    def disconnect(self):
        self.client.disconnect()
        self.is_running = False

    def enumerate_topics(self) -> list[str]:
        return sorted(list(self.topics_seen))

    def capture(self, duration: int = 60, topic_filter: str = "#") -> list[CapturedMessage]:
        self.messages.clear()
        self.client.subscribe(topic_filter, qos=0)
        self.client.loop_start()
        start = time.time()
        console.print(f"[yellow][MQTT] Capturing '{topic_filter}' for {duration}s...[/yellow]")
        while time.time() - start < duration:
            remaining = int(duration - (time.time() - start))
            print(f"\r[MQTT] {len(self.messages)} messages | {remaining}s left    ", end="")
            time.sleep(1)
        self.client.loop_stop()
        console.print(f"\n[green][MQTT] Done: {len(self.messages)} messages captured[/green]")
        return self.messages

    def print_topic_table(self):
        table = Table(title="[bold]Discovered MQTT Topics[/bold]")
        table.add_column("Topic", style="cyan")
        table.add_column("Messages", style="green", justify="right")
        table.add_column("Avg Size (bytes)", style="yellow", justify="right")
        topic_stats: dict[str, list] = {}
        for msg in self.messages:
            topic_stats.setdefault(msg.topic, []).append(msg.payload_size())
        for topic, sizes in sorted(topic_stats.items()):
            avg = sum(sizes) // len(sizes)
            table.add_row(topic, str(len(sizes)), str(avg))
        console.print(table)
