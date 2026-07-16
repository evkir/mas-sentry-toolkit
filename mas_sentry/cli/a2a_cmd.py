# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()
err_console = Console(stderr=True)


@app.command("scan")
def a2a_scan(
    target: str = typer.Option(..., "--target", "-t", help="http(s)://agent-host[:port] (A2A base URL)"),
    out: Path = typer.Option(Path("reports/a2a.json"), "--out", "-o"),
    active: bool = typer.Option(
        False,
        "--active",
        help="Run live probes (submits tasks): task-id collision, unauthorized cancel, IPI canary",
    ),
    confirm_scope: bool = typer.Option(
        False,
        "--confirm-scope",
        help="Required for non-lab targets (anything outside localhost/.lab/.test/.local)",
    ),
) -> None:
    """Scan an A2A agent endpoint: discover -> card audit -> optional active probes.

    Passive by default (fetch + audit the AgentCard). Localhost/lab targets
    bypass --confirm-scope; any other target requires it even for the passive
    fetch. Output JSON feeds `mas-sentry report convert` for html/md/sarif/junit.
    """
    if not target.startswith(("http://", "https://")):
        raise typer.BadParameter("target must be an http(s):// URL")
    if active:
        err_console.print(
            f"[authorized use] Active A2A probing against {target} submits tasks to the endpoint. "
            "Run only on systems you own or are authorized to test.",
            markup=False,
            soft_wrap=True,
        )

    from mas_sentry.core.scope import ScopeViolation
    from mas_sentry.protocols.a2a.runtime import run_a2a_scan

    try:
        findings = run_a2a_scan(target=target, out=out, scope_confirmed=confirm_scope, active=active)
    except ScopeViolation as exc:
        err_console.print(f"[scope] {exc}", markup=False, soft_wrap=True)
        raise typer.Exit(code=2) from exc

    mode = "active" if active else "passive"
    table = Table(title=f"A2A scan ({mode}) - {target}")
    table.add_column("Module")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Tags")
    for f in findings:
        table.add_row(f.module, f.severity.value, f.title[:60], ", ".join(f.tags))
    console.print(table)
    console.print(f"[green]{len(findings)} finding(s) -> {out}[/green]")


@app.command("mesh")
def a2a_mesh(
    manifest: Path = typer.Option(..., "--manifest", "-m", help="Delegation-mesh manifest JSON: {agents, edges}"),
    out: Path = typer.Option(Path("reports/a2a-mesh.json"), "--out", "-o"),
    confirm_scope: bool = typer.Option(
        False,
        "--confirm-scope",
        help="Required for non-lab agent URLs (anything outside localhost/.lab/.test/.local)",
    ),
) -> None:
    """Audit an A2A delegation mesh: fetch every card -> delegation graph -> flag escalation.

    Passive (card discovery only, no tasks submitted). Each agent URL is scope-checked
    individually, so any non-lab agent in the manifest requires --confirm-scope. Output
    JSON feeds `mas-sentry report convert` for html/md/sarif/junit.
    """
    from mas_sentry.core.scope import ScopeViolation
    from mas_sentry.protocols.a2a.runtime import run_mesh_scan

    try:
        findings = run_mesh_scan(manifest=manifest, out=out, scope_confirmed=confirm_scope)
    except ScopeViolation as exc:
        err_console.print(f"[scope] {exc}", markup=False, soft_wrap=True)
        raise typer.Exit(code=2) from exc
    except (ValueError, OSError) as exc:
        err_console.print(f"[manifest] {exc}", markup=False, soft_wrap=True)
        raise typer.Exit(code=2) from exc

    table = Table(title=f"A2A delegation-mesh scan - {manifest.name}")
    table.add_column("Module")
    table.add_column("Severity")
    table.add_column("Title")
    for f in findings:
        table.add_row(f.module, f.severity.value, f.title[:70])
    console.print(table)
    console.print(f"[green]{len(findings)} mesh finding(s) -> {out}[/green]")
