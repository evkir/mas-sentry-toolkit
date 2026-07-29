# SPDX-License-Identifier: AGPL-3.0-or-later
import contextlib
import time
from typing import Any

import paho.mqtt.client as mqtt
from rich.console import Console
from rich.panel import Panel

from mas_sentry.core.scope import assert_in_scope
from mas_sentry.protocols.mqtt_connect import BrokerUnreachable, await_connack

console = Console()


class MQTTBrokerFingerprinter:
    """Identify broker type and version via $SYS topic analysis"""

    def __init__(self, host: str, port: int = 1883, confirmed: bool = False):
        assert_in_scope(host, confirmed=confirmed)
        self.host = host
        self.port = port
        self.sys_topics: dict[str, str] = {}

    def fingerprint(self) -> dict[str, Any]:
        """Read $SYS and identify the broker.

        Raises BrokerUnreachable / BrokerRefusedConnection rather than returning
        a dict with broker_type "unreachable": a failure encoded as a normal
        return value is a failure the caller can forget to check, and this one
        was reported by a different mechanism than the two sibling probes used.
        """
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="mas-sentry-fp")
        client.on_message = lambda c, u, msg: self.sys_topics.__setitem__(
            msg.topic, msg.payload.decode(errors="replace")
        )
        state: dict[str, Any] = {}

        def on_connect(c, u, f, rc, properties=None):
            state["rc"] = rc
            if rc == 0:
                c.subscribe("$SYS/#", qos=0)

        client.on_connect = on_connect
        try:
            client.connect(self.host, self.port, keepalive=5)
        except (OSError, TimeoutError) as exc:
            raise BrokerUnreachable(f"{self.host}:{self.port} unreachable: {exc}") from exc

        client.loop_start()
        try:
            await_connack(state)
            time.sleep(4)
        finally:
            client.loop_stop()
            with contextlib.suppress(OSError):
                client.disconnect()

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
