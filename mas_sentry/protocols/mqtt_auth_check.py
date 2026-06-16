# SPDX-License-Identifier: AGPL-3.0-or-later
import contextlib
import time

import paho.mqtt.client as mqtt
from rich.console import Console

from mas_sentry.core.scope import assert_in_scope

console = Console()


class BrokerUnreachable(ConnectionError):
    """Raised when the broker cannot be reached at the transport level.

    Distinct from an authentication rejection: unreachable must never be
    reported as "authentication enforced".
    """


class MQTTAuthChecker:
    """Test MQTT broker authentication posture"""

    def __init__(self, host: str, port: int = 1883, confirmed: bool = False):
        assert_in_scope(host, confirmed=confirmed)
        self.host = host
        self.port = port

    def _try_connect(self, username: str | None = None, password: str | None = None, label: str = "test") -> bool:
        result = {"ok": False}
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"mas-check-{label[:6]}")

        def on_connect(c, u, f, rc, properties=None):
            result["ok"] = rc == 0

        client.on_connect = on_connect
        if username is not None:
            client.username_pw_set(username, password)
        try:
            client.connect(self.host, self.port, keepalive=4)
        except (OSError, TimeoutError) as exc:
            raise BrokerUnreachable(f"{self.host}:{self.port} unreachable: {exc}") from exc
        try:
            client.loop_start()
            time.sleep(2)
        finally:
            client.loop_stop()
            with contextlib.suppress(OSError):
                client.disconnect()
        return result["ok"]

    def run_all(self) -> dict[str, bool]:
        results: dict[str, bool] = {}
        console.print("[bold yellow][AUTH] Testing broker authentication...[/bold yellow]")
        try:
            anon = self._try_connect(label="anon")
            results["anonymous_access"] = anon
            if anon:
                console.print("[bold red]  [CRITICAL] Anonymous access ALLOWED![/bold red]")
            else:
                console.print("[green]  [+] Anonymous access denied[/green]")

            guest = self._try_connect("guest", "guest", label="guest")
            results["default_guest"] = guest
            if guest:
                console.print("[bold red]  [HIGH] Default guest:guest credentials work![/bold red]")
            else:
                console.print("[green]  [+] guest:guest rejected[/green]")

            admin = self._try_connect("admin", "admin", label="admin")
            results["default_admin"] = admin
            if admin:
                console.print("[bold red]  [HIGH] Default admin:admin credentials work![/bold red]")
            else:
                console.print("[green]  [+] admin:admin rejected[/green]")
        except BrokerUnreachable as exc:
            console.print(f"[bold red]  [AUTH] broker unreachable, cannot assess: {exc}[/bold red]")
        return results
