# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("scan")
def amqp_scan(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="host[:mgmt_port] (default management port 15672, NOT the 5672 AMQP port)",
    ),
    username: str = typer.Option("guest", "--username", "-u"),
    password: str = typer.Option("guest", "--password", "-p"),
    vhost: str = typer.Option("%2F", "--vhost", help="URL-encoded vhost; default is / encoded as %2F"),
    out: Path = typer.Option(Path("reports/amqp.json"), "--out", "-o"),
    confirm_scope: bool = typer.Option(
        False,
        "--confirm-scope",
        help="Required for non-lab targets (anything outside localhost/.lab/.test/.local)",
    ),
) -> None:
    """Audit a RabbitMQ management API (HTTP, port 15672)."""
    from mas_sentry.core.scope import ScopeViolation
    from mas_sentry.protocols.amqp_runtime import parse_target, run_amqp_scan

    try:
        host, mgmt_port = parse_target(target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        findings = run_amqp_scan(
            host=host,
            mgmt_port=mgmt_port,
            username=username,
            password=password,
            vhost=vhost,
            out=out,
            scope_confirmed=confirm_scope,
        )
    except ScopeViolation as exc:
        raise typer.BadParameter(str(exc)) from exc

    table = Table(title=f"AMQP management scan - {host}:{mgmt_port}")
    table.add_column("Severity")
    table.add_column("Title")
    for f in findings:
        table.add_row(f.severity.value, f.title[:80])
    console.print(table)
    console.print(f"[green]wrote {len(findings)} findings -> {out}[/green]")
