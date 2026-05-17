# SPDX-License-Identifier: AGPL-3.0-or-later
"""
mas_sentry/core/multi_target.py
Multi-target scan support.
DAY 14 — Commit 2
"""

import threading
from typing import Any

from rich import box
from rich.console import Console
from rich.table import Table

from mas_sentry.protocols.auto_detect import detect_protocol

console = Console()


class MultiTargetScanner:
    """
    Run protocol detection against multiple targets in parallel.
    """

    def __init__(self, targets: list[str], port: int | None = None, threads: int = 5):
        self.targets = targets
        self.port = port
        self.threads = threads
        self.results: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _scan_one(self, host: str) -> None:
        result = detect_protocol(host, self.port)
        with self._lock:
            self.results.append(result)

    def run(self) -> list[dict[str, Any]]:
        console.print(
            f"[bold yellow][MULTI] Scanning {len(self.targets)} targets with {self.threads} threads...[/bold yellow]"
        )

        active = []
        for host in self.targets:
            t = threading.Thread(target=self._scan_one, args=(host,), daemon=True)
            t.start()
            active.append(t)
            if len(active) >= self.threads:
                for t in active:
                    t.join()
                active = []

        for t in active:
            t.join()

        self._print_results()
        return self.results

    def _print_results(self) -> None:
        table = Table(
            title="🎯 Multi-Target Scan Results",
            box=box.ROUNDED,
            header_style="bold magenta",
        )
        table.add_column("Host")
        table.add_column("Port", width=6)
        table.add_column("Protocol", width=10)
        table.add_column("Confidence", width=12)
        table.add_column("Banner")

        for r in self.results:
            proto = r.get("protocol", "unknown")
            color = {
                "mqtt": "green",
                "amqp": "cyan",
                "tcp": "yellow",
                "unknown": "red",
            }.get(proto, "white")

            table.add_row(
                r.get("host", "?"),
                str(r.get("port", "?")),
                f"[{color}]{proto}[/{color}]",
                r.get("confidence", "?"),
                (r.get("banner") or "")[:40],
            )

        console.print(table)

    def mqtt_targets(self) -> list[str]:
        return [r["host"] for r in self.results if r.get("protocol") == "mqtt"]

    def amqp_targets(self) -> list[str]:
        return [r["host"] for r in self.results if r.get("protocol") == "amqp"]
