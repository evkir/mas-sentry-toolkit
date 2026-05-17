# SPDX-License-Identifier: AGPL-3.0-or-later
import time
from typing import Any

import paho.mqtt.client as mqtt
from rich.console import Console
from rich.panel import Panel

console = Console()


class MQTTBrokerFingerprinter:
    """Identify broker type and version via $SYS topic analysis"""

    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port
        self.sys_topics: dict[str, str] = {}

    def fingerprint(self) -> dict[str, Any]:
        client = mqtt.Client(client_id="mas-sentry-fp")
        client.on_message = lambda c, u, msg: self.sys_topics.__setitem__(
            msg.topic, msg.payload.decode(errors="replace")
        )
        client.on_connect = lambda c, u, f, rc: c.subscribe("$SYS/#", qos=0)

        try:
            client.connect(self.host, self.port, keepalive=5)
            client.loop_start()
            time.sleep(4)
            client.loop_stop()
            client.disconnect()
        except Exception as e:
            return {"error": str(e), "broker_type": "unreachable"}

        broker_type = self._identify()
        result = {
            "broker_type": broker_type,
            "sys_topics_count": len(self.sys_topics),
            "version": self.sys_topics.get("$SYS/broker/version", "unknown"),
            "uptime": self.sys_topics.get("$SYS/broker/uptime", "unknown"),
            "clients_connected": self.sys_topics.get("$SYS/broker/clients/connected", "unknown"),
            "messages_received": self.sys_topics.get("$SYS/broker/messages/received", "unknown"),
        }

        console.print(
            Panel(
                f"[bold cyan]Broker:[/bold cyan] {result['broker_type']}\n"
                f"[bold cyan]Version:[/bold cyan] {result['version']}\n"
                f"[bold cyan]Uptime:[/bold cyan] {result['uptime']}\n"
                f"[bold cyan]Clients:[/bold cyan] {result['clients_connected']}\n"
                f"[bold cyan]$SYS topics:[/bold cyan] {result['sys_topics_count']}",
                title="[bold red]Broker Fingerprint[/bold red]",
            )
        )
        return result

    def _identify(self) -> str:
        version = self.sys_topics.get("$SYS/broker/version", "").lower()
        if "mosquitto" in version:
            return "Eclipse Mosquitto"
        if "hivemq" in version:
            return "HiveMQ"
        if "emqx" in version:
            return "EMQX"
        if self.sys_topics:
            return "Unknown ($SYS accessible)"
        return "Unknown (no $SYS response)"
