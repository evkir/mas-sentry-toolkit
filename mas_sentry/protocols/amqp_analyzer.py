# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import urllib.error
import urllib.request
from typing import Any

from rich.console import Console
from rich.table import Table

from .base import BaseProtocolAnalyzer, CapturedMessage

console = Console()


class AMQPAnalyzer(BaseProtocolAnalyzer):
    """
    AMQP analyzer using RabbitMQ Management API (port 15672).
    Enumerates exchanges, queues, bindings, and connections
    without requiring a full AMQP client library.
    """

    def __init__(
        self,
        host: str,
        port: int = 5672,
        username: str = "guest",
        password: str = "guest",
        mgmt_port: int = 15672,
        vhost: str = "%2F",
    ):
        super().__init__(host, port)
        self.username = username
        self.password = password
        self.mgmt_port = mgmt_port
        self.vhost = vhost
        self.exchanges: list[dict] = []
        self.queues: list[dict] = []
        self.bindings: list[dict] = []
        self.connections: list[dict] = []

    def _api_get(self, path: str) -> Any | None:
        url = f"http://{self.host}:{self.mgmt_port}/api/{path}"
        req = urllib.request.Request(url)
        import base64

        creds = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        req.add_header("Authorization", f"Basic {creds}")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:  # nosec B310
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            console.print(f"[red][AMQP] API error {e.code} on {path}[/red]")
            return None
        except Exception as e:
            console.print(f"[red][AMQP] Cannot reach management API: {e}[/red]")
            return None

    def connect(self) -> bool:
        data = self._api_get("overview")
        if data:
            console.print(f"[bold green][AMQP] Management API accessible at {self.host}:{self.mgmt_port}[/bold green]")
            console.print(f"[green][AMQP] RabbitMQ version: {data.get('rabbitmq_version', 'unknown')}[/green]")
            self.is_running = True
            return True
        return False

    def disconnect(self):
        self.is_running = False

    def capture(self, duration: int = 30) -> list[CapturedMessage]:
        console.print("[yellow][AMQP] Capture via management API — use enumerate_topics() for full audit[/yellow]")
        return self.messages

    def enumerate_topics(self) -> list[str]:
        return [q.get("name", "") for q in self.queues]

    def enumerate_exchanges(self) -> list[dict]:
        data = self._api_get(f"exchanges/{self.vhost}")
        if not data:
            return []
        self.exchanges = data

        table = Table(title="[bold]AMQP Exchanges[/bold]")
        table.add_column("Name", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Durable", style="green")
        table.add_column("Auto-delete", style="red")

        for ex in self.exchanges:
            name = ex.get("name") or "[default]"
            table.add_row(
                name,
                ex.get("type", "?"),
                str(ex.get("durable", False)),
                str(ex.get("auto_delete", False)),
            )
        console.print(table)
        return self.exchanges

    def enumerate_queues(self) -> list[dict]:
        data = self._api_get(f"queues/{self.vhost}")
        if not data:
            return []
        self.queues = data

        table = Table(title="[bold]AMQP Queues[/bold]")
        table.add_column("Name", style="cyan")
        table.add_column("Messages", style="yellow", justify="right")
        table.add_column("Consumers", style="green", justify="right")
        table.add_column("Durable", style="blue")

        for q in self.queues:
            table.add_row(
                q.get("name", "?"),
                str(q.get("messages", 0)),
                str(q.get("consumers", 0)),
                str(q.get("durable", False)),
            )
        console.print(table)
        return self.queues

    def enumerate_connections(self) -> list[dict]:
        data = self._api_get("connections")
        if not data:
            return []
        self.connections = data

        table = Table(title="[bold]Active AMQP Connections[/bold]")
        table.add_column("Client", style="cyan")
        table.add_column("Host", style="yellow")
        table.add_column("User", style="red")
        table.add_column("State", style="green")

        for c in self.connections:
            table.add_row(
                c.get("client_properties", {}).get("connection_name", "unknown"),
                c.get("peer_host", "?"),
                c.get("user", "?"),
                c.get("state", "?"),
            )
        console.print(table)
        return self.connections

    def check_default_credentials(self) -> bool:
        """Check if guest:guest works (RabbitMQ default)"""
        original_user = self.username
        original_pass = self.password
        self.username = "guest"
        self.password = "guest"
        result = self._api_get("overview")
        self.username = original_user
        self.password = original_pass
        if result:
            console.print("[bold red][!] CRITICAL: RabbitMQ accessible with default guest:guest![/bold red]")
            return True
        console.print("[green][+] Default guest:guest credentials rejected[/green]")
        return False

    def full_audit(self):
        """Run complete AMQP enumeration"""
        console.print("[bold cyan][AMQP] Starting full audit...[/bold cyan]")
        self.check_default_credentials()
        self.enumerate_exchanges()
        self.enumerate_queues()
        self.enumerate_connections()
        console.print(
            f"[bold green][AMQP] Audit complete: {len(self.exchanges)} exchanges, "
            f"{len(self.queues)} queues, {len(self.connections)} connections[/bold green]"
        )
