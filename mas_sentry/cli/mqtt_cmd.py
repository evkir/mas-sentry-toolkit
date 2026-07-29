# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("scan")
def mqtt_scan(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="mqtt://host[:port] | host[:port] (default port 1883)",
    ),
    checks: str = typer.Option("all", "--checks", help="all|auth|fingerprint|topics (comma-separated)"),
    duration: int = typer.Option(20, "--duration", "-d", help="Topic collection seconds"),
    out: Path = typer.Option(Path("reports/mqtt.json"), "--out", "-o"),
    confirm_scope: bool = typer.Option(
        False,
        "--confirm-scope",
        help="Required for non-lab targets (anything outside localhost/.lab/.test/.local)",
    ),
) -> None:
    """Audit an MQTT broker. Localhost/lab targets bypass --confirm-scope."""
    from mas_sentry.core.scope import ScopeViolation
    from mas_sentry.protocols.mqtt_runtime import ALL_CHECKS, parse_target, run_mqtt_scan

    try:
        host, port = parse_target(target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if checks != "all":
        unknown = [c.strip() for c in checks.split(",") if c.strip() not in ALL_CHECKS]
        if unknown:
            raise typer.BadParameter(f"unknown check(s): {', '.join(unknown)} (valid: {', '.join(ALL_CHECKS)})")

    try:
        findings = run_mqtt_scan(
            host=host,
            port=port,
            checks=checks,
            duration=duration,
            out=out,
            scope_confirmed=confirm_scope,
        )
    except ScopeViolation as exc:
        raise typer.BadParameter(str(exc)) from exc

    table = Table(title=f"MQTT scan - {host}:{port}")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Title")
    for f in findings:
        table.add_row(f.module.removeprefix("mqtt."), f.severity.value, f.title[:80])
    console.print(table)
    console.print(f"[green]wrote {len(findings)} findings -> {out}[/green]")
