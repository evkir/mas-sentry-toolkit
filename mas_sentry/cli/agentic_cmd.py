# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.table import Table

from mas_sentry.core.console import make_console

from .fail_on import FAIL_ON_HELP, enforce_fail_on, validate_fail_on

if TYPE_CHECKING:
    from mas_sentry.agentic.tool_misuse import ToolInventoryEntry

app = typer.Typer(no_args_is_help=True)
console = make_console()
err_console = make_console(stderr=True)


@app.command("scan")
def agentic_scan(
    target: str = typer.Option(..., "--target", "-t", help="Logical name or URL of agent system"),
    asi: str = typer.Option("all", "--asi", help="all, asi02, asi03, asi04, or a module name"),
    tools_file: Path | None = typer.Option(None, "--tools-file", exists=True, help="JSON: list of {name, description}"),
    token: str | None = typer.Option(None, "--token", help="JWT to audit (ASI03)"),
    requirements: Path | None = typer.Option(None, "--requirements", exists=True, help="requirements.txt"),
    out: Path = typer.Option(Path("reports/agentic.json"), "--out", "-o"),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help=FAIL_ON_HELP, callback=validate_fail_on, show_default=False
    ),
) -> None:
    """Static agentic scan. The live ASI01/ASI06 probes need a transport.

    Exits 2 when no module ran, and when any selected module raised. A report
    from a scan that checked nothing is byte-identical to a clean one, and one
    from a scan that stopped halfway is byte-identical to a complete one. What
    a caller reads is the exit code, so both have to be the loud case.
    """
    from mas_sentry.agentic.run import no_coverage_reason, run_static_scan

    ctx = {
        "target": target,
        "tools": _load_tools(tools_file),
        "token": token or "",
        "requirements_path": requirements,
        "selected": asi,
    }
    run = run_static_scan(ctx)

    # The crash check comes first on purpose. A module that raised leaves
    # modules_ran empty just as an unfed one does, and no_coverage_reason
    # would then tell the operator to pass the flag they already passed,
    # burying the fault that actually stopped the scan.
    if run.errors:
        for entry in run.errors:
            err_console.print(
                f"module {entry['module']} raised: {entry['error']}",
                markup=False,
                soft_wrap=True,
            )
        selected_count = len(run.errors) + len(run.modules_ran)
        err_console.print(
            f"scan incomplete: {len(run.errors)} of {selected_count} selected module(s) raised, "
            "so no report is written",
            markup=False,
            soft_wrap=True,
        )
        raise typer.Exit(2)

    if not run.modules_ran:
        err_console.print(no_coverage_reason(asi))
        raise typer.Exit(2)

    findings = run.findings
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
    enforce_fail_on([f.severity.value for f in findings], fail_on)


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
