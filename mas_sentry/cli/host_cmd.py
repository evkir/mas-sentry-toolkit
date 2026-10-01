# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import platform
from pathlib import Path

import typer
from rich.table import Table

from mas_sentry.core.console import make_console

from .fail_on import FAIL_ON_HELP, enforce_fail_on, validate_fail_on

app = typer.Typer(no_args_is_help=True)
console = make_console()


@app.command("audit")
def host_audit(
    home: Path = typer.Option(
        None,
        "--home",
        help="Home directory to audit. Defaults to this user's. A responder examining a mounted "
        "disk image or another account on a shared machine points it elsewhere",
        show_default=False,
    ),
    project_root: Path = typer.Option(
        None,
        "--project-root",
        "-p",
        help="Repository whose committed configs are audited. Defaults to the current directory",
        show_default=False,
    ),
    out: Path = typer.Option(Path("reports/host.json"), "--out", "-o"),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help=FAIL_ON_HELP, callback=validate_fail_on, show_default=False
    ),
) -> None:
    """Audit the agent host: which configs exist, what they declare, what went unread.

    No --confirm-scope: this reads the operator's own machine rather than a
    target over the network, so there is nobody else to authorise. Nothing is
    sent anywhere and no value from a config enters the report - env and header
    names are recorded, their contents are not.

    Output JSON feeds `mas-sentry report convert` for html/md/sarif/junit.
    """
    from mas_sentry.host.runtime import run_host_audit

    findings = run_host_audit(
        home=home if home is not None else Path.home(),
        project_root=project_root if project_root is not None else Path.cwd(),
        system=platform.system(),
        out=out,
    )

    table = Table(title="Agent-host posture audit")
    table.add_column("Module")
    table.add_column("Severity")
    table.add_column("Title")
    for f in findings:
        table.add_row(f.module, f.severity.value, f.title[:70])
    console.print(table)
    console.print(f"[green]{len(findings)} finding(s) -> {out}[/green]")
    enforce_fail_on([f.severity.value for f in findings], fail_on)
