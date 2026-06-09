# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from mas_sentry.agentic.tool_misuse import ToolInventoryEntry

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("scan")
def agentic_scan(
    target: str = typer.Option(..., "--target", "-t", help="Logical name or URL of agent system"),
    asi: str = typer.Option("all", "--asi", help="all|asi01|asi02|...|asi10"),
    tools_file: Path | None = typer.Option(None, "--tools-file", help="JSON: list of {name, description}"),
    token: str | None = typer.Option(None, "--token", help="JWT to audit (ASI03)"),
    requirements: Path | None = typer.Option(None, "--requirements", help="requirements.txt"),
    out: Path = typer.Option(Path("reports/agentic.json"), "--out", "-o"),
) -> None:
    """Static agentic scan. Live ASI01/ASI04 probes need a transport."""
    from mas_sentry.agentic.run import run_static_scan

    ctx = {
        "target": target,
        "tools": _load_tools(tools_file),
        "token": token or "",
        "requirements_path": requirements,
        "selected": asi,
    }
    findings = run_static_scan(ctx)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps([f.to_dict() for f in findings], indent=2, default=str))

    table = Table(title=f"Agentic scan — {target}")
    table.add_column("ASI")
    table.add_column("Severity")
    table.add_column("Title")
    for f in findings:
        asi_tag = next((t for t in f.tags if t.startswith("ASI")), "-")
        table.add_row(asi_tag, f.severity.value, f.title[:80])
    console.print(table)
    console.print(f"[dim]{len(findings)} finding(s) written to {out}[/dim]")


def _load_tools(path: Path | None) -> list[ToolInventoryEntry]:
    from mas_sentry.agentic.tool_misuse import ToolInventoryEntry

    if not path or not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise typer.BadParameter(f"--tools-file must contain a JSON array, got {type(raw).__name__}")
    return [
        ToolInventoryEntry(
            name=t["name"],
            description=t.get("description", ""),
            requires_confirmation=t.get("requires_confirmation", False),
        )
        for t in raw
    ]
