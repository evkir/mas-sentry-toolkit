# SPDX-License-Identifier: AGPL-3.0-or-later
import paho.mqtt.client as mqtt
import time
from typing import Dict
from rich.console import Console

console = Console()

class MQTTAuthChecker:
    """Test MQTT broker authentication posture"""

    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port

    def _try_connect(self, username: str = None, password: str = None,
                     label: str = "test") -> bool:
        result = {"ok": False}
        client = mqtt.Client(client_id=f"mas-check-{label[:6]}")

        def on_connect(c, u, f, rc):
            result["ok"] = (rc == 0)

        client.on_connect = on_connect
        if username is not None:
            client.username_pw_set(username, password)
        try:
            client.connect(self.host, self.port, keepalive=4)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()
        except Exception:
            pass
        return result["ok"]

    def run_all(self) -> Dict[str, bool]:
        results = {}

        console.print("[bold yellow][AUTH] Testing broker authentication...[/bold yellow]")

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

        return results
