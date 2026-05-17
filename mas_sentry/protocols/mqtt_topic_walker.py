# SPDX-License-Identifier: AGPL-3.0-or-later
import paho.mqtt.client as mqtt
import time
from typing import Set, List
from rich.tree import Tree
from rich.console import Console

console = Console()

class MQTTTopicWalker:
    """Enumerate full MQTT topic tree using wildcard subscriptions"""

    WILDCARDS = ["#", "+/#", "+/+/#", "+/+/+/#"]

    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port
        self.discovered: Set[str] = set()

    def walk(self, duration: int = 20) -> List[str]:
        client = mqtt.Client(client_id="mas-sentry-walker")
        client.on_message = lambda c, u, msg: self.discovered.add(msg.topic)

        def on_connect(c, u, f, rc):
            if rc == 0:
                for wc in self.WILDCARDS:
                    c.subscribe(wc, qos=0)
                console.print(f"[yellow][WALKER] Subscribed with wildcards, collecting {duration}s...[/yellow]")

        client.on_connect = on_connect
        client.connect(self.host, self.port)
        client.loop_start()
        time.sleep(duration)
        client.loop_stop()
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
                        "_children": {}
                    }
                current_node = current_dict[part]["_node"]
                current_dict = current_dict[part]["_children"]

        console.print(tree)
