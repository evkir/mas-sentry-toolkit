# SPDX-License-Identifier: AGPL-3.0-or-later
"""
mas_sentry/protocols/auto_detect.py
Automatic protocol detection — MQTT vs AMQP.
DAY 14 — Commit 1
"""

import socket
import time

import paho.mqtt.client as mqtt
from rich.console import Console

console = Console()


class ProtocolDetector:
    """
    Auto-detect which protocol is running on a host:port.
    Tries MQTT first, then AMQP, then falls back to TCP banner grab.
    """

    MQTT_DEFAULT_PORT = 1883
    AMQP_DEFAULT_PORT = 5672
    TIMEOUT = 3

    def __init__(self, host: str):
        self.host = host
        self.result = {
            "host": host,
            "protocol": None,
            "port": None,
            "banner": None,
            "confidence": None,
        }

    def detect(self, port: int | None = None) -> dict:
        """
        Run detection. If port is given, test only that port.
        Otherwise try both defaults.
        """
        if port:
            self.result["port"] = port
            self._try_port(port)
        else:
            for p in [self.MQTT_DEFAULT_PORT, self.AMQP_DEFAULT_PORT]:
                if self._try_port(p):
                    break

        if not self.result["protocol"]:
            self.result["protocol"] = "unknown"
            self.result["confidence"] = "low"

        console.print(
            f"[bold cyan][DETECT] {self.host}:{self.result['port']} → "
            f"{self.result['protocol']} ({self.result['confidence']})[/bold cyan]"
        )
        return self.result

    def _try_port(self, port: int) -> bool:
        if not self._is_open(port):
            return False

        if self._try_mqtt(port):
            return True
        if self._try_amqp(port):
            return True

        banner = self._grab_banner(port)
        if banner:
            self.result["banner"] = banner
            self.result["port"] = port
            self.result["protocol"] = "tcp"
            self.result["confidence"] = "low"
            return True

        return False

    def _is_open(self, port: int) -> bool:
        try:
            with socket.create_connection((self.host, port), timeout=self.TIMEOUT):
                return True
        except Exception:
            return False

    def _try_mqtt(self, port: int) -> bool:
        connected = {"ok": False}
        client = mqtt.Client(client_id="mas-sentry-detect")
        client.on_connect = lambda c, u, f, rc: connected.update({"ok": rc == 0})
        try:
            client.connect(self.host, port, keepalive=3)
            client.loop_start()
            time.sleep(2)
            client.loop_stop()
            client.disconnect()
        except Exception:
            return False

        if connected["ok"]:
            self.result["protocol"] = "mqtt"
            self.result["port"] = port
            self.result["confidence"] = "high"
            return True
        return False

    def _try_amqp(self, port: int) -> bool:
        """Check AMQP by looking for AMQP handshake bytes in banner."""
        banner = self._grab_banner(port)
        if banner and "AMQP" in banner:
            self.result["protocol"] = "amqp"
            self.result["port"] = port
            self.result["banner"] = banner
            self.result["confidence"] = "high"
            return True
        return False

    def _grab_banner(self, port: int) -> str:
        try:
            with socket.create_connection((self.host, port), timeout=self.TIMEOUT) as s:
                s.sendall(b"\n")
                data = s.recv(256)
                return data.decode(errors="replace").strip()
        except Exception:
            return ""


def detect_protocol(host: str, port: int | None = None) -> dict:
    """Convenience wrapper."""
    return ProtocolDetector(host).detect(port)
