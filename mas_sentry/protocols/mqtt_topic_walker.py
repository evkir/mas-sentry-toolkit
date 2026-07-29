# SPDX-License-Identifier: AGPL-3.0-or-later
import contextlib
import time
from typing import Any, ClassVar

import paho.mqtt.client as mqtt
from rich.console import Console
from rich.tree import Tree

from mas_sentry.core.scope import assert_in_scope
from mas_sentry.protocols.mqtt_connect import BrokerUnreachable, await_connack

console = Console()


class MQTTTopicWalker:
    """Enumerate full MQTT topic tree using wildcard subscriptions"""

    WILDCARDS: ClassVar[list[str]] = ["#", "+/#", "+/+/#", "+/+/+/#"]

    def __init__(self, host: str, port: int = 1883, confirmed: bool = False):
        assert_in_scope(host, confirmed=confirmed)
        self.host = host
        self.port = port
        self.discovered: set[str] = set()

    def walk(self, duration: int = 20) -> list[str]:
        """Collect every topic the broker will hand an anonymous wildcard subscriber.

        Raises BrokerUnreachable if the broker never answers and
        BrokerRefusedConnection if it answers and rejects the CONNECT. Both used
        to end as an empty list, which is also what an idle broker returns - so
        a refused subscription was reported as "no topics found".
        """
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="mas-sentry-walker")
        client.on_message = lambda c, u, msg: self.discovered.add(msg.topic)
        state: dict[str, Any] = {}

        def on_connect(c, u, f, rc, properties=None):
            state["rc"] = rc
            if rc == 0:
                for wc in self.WILDCARDS:
                    c.subscribe(wc, qos=0)
                console.print(f"[yellow][WALKER] Subscribed with wildcards, collecting {duration}s...[/yellow]")

        client.on_connect = on_connect
        try:
            client.connect(self.host, self.port)
        except (OSError, TimeoutError) as exc:
            raise BrokerUnreachable(f"{self.host}:{self.port} unreachable: {exc}") from exc

        client.loop_start()
        try:
            await_connack(state)
            time.sleep(duration)
        finally:
            client.loop_stop()
            with contextlib.suppress(OSError):
                client.disconnect()

        self._print_tree()
        console.print(f"[green][WALKER] Found {len(self.discovered)} unique topics[/green]")
        return sorted(self.discovered)

    def _print_tree(self):
        tree = Tree("[bold red]MQTT Topic Tree[/bold red]")
        nodes: dict = {}

        for topic in sorted(self.discovered):
            parts = topic.split("/")
            current_dict = nodes
            current_node = tree
            for part in parts:
                if part not in current_dict:
                    current_dict[part] = {
                        "_node": current_node.add(f"[cyan]{part}[/cyan]"),
                        "_children": {},
                    }
                current_node = current_dict[part]["_node"]
                current_dict = current_dict[part]["_children"]

        console.print(tree)
