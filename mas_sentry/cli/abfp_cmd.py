# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("scan")
def abfp_scan(
    target: str = typer.Option(..., "--target", "-t", help="mqtt://host:port"),
    duration: int = typer.Option(60, "--duration", "-d", help="Passive collection seconds"),
    baseline_threshold: int = typer.Option(500, "--threshold", help="Min messages per agent"),
    out: Path = typer.Option(Path("reports/abfp.json"), "--out", "-o"),
) -> None:
    """Run a single-shot ABFP scan: passive learn -> fingerprint -> score."""
    from mas_sentry.agents.abfp.runtime import run_abfp_scan

    findings = run_abfp_scan(
        target=target,
        duration=duration,
        baseline_threshold=baseline_threshold,
        out_path=out,
    )
    table = Table(title=f"ABFP — {target}")
    table.add_column("Agent")
    table.add_column("Score", justify="right")
    table.add_column("Severity")
    for f in findings:
        table.add_row(f.agent_id, str(f.score.total), f.score.severity.value)
    console.print(table)
