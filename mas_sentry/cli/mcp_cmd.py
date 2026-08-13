# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import shlex
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(no_args_is_help=True)
console = Console()


def _parse_target(target: str) -> tuple[str, str | list[str]]:
    """Return (scheme, command-or-url).

    For stdio targets the part after 'stdio://' is shell-tokenised so the
    user can pass arguments naturally:
        --target 'stdio://python3 ./server.py --root /tmp/lab'
    """
    if target.startswith("stdio://"):
        rest = target[len("stdio://") :]
        if not rest:
            raise typer.BadParameter("stdio:// must be followed by a command")
        return "stdio", shlex.split(rest)
    if target.startswith(("http://", "https://")):
        return target.split("://", 1)[0], target
    raise typer.BadParameter(f"Unsupported target scheme: {target}")


@app.command("scan")
def mcp_scan(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="stdio://<cmd args...> | http(s)://host:port/mcp",
    ),
    checks: str = typer.Option(
        "all", "--checks", help="all|fingerprint|poisoning|ssrf|traversal|rebind|drift|resources|desync|mutation"
    ),
    out: Path = typer.Option(Path("reports/mcp.json"), "--out", "-o"),
    tool_baseline: Path | None = typer.Option(
        None,
        "--tool-baseline",
        help="Path to a tool-descriptor baseline; captured on first run, diffed for rug-pull/drift after",
    ),
    confirm_scope: bool = typer.Option(
        False,
        "--confirm-scope",
        help="Required for non-lab targets (anything outside localhost/.lab/.test/.local)",
    ),
) -> None:
    """Scan an MCP server. Localhost/lab targets bypass --confirm-scope."""
    from mas_sentry.protocols.mcp.runtime import run_mcp_scan

    scheme, command = _parse_target(target)
    findings = run_mcp_scan(
        scheme=scheme,
        command=command,
        target_label=target,
        checks=checks,
        out=out,
        scope_confirmed=confirm_scope,
        tool_baseline=tool_baseline,
    )
    table = Table(title=f"MCP scan — {target}")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Detail")
    for f in findings:
        table.add_row(f["check"], f["severity"], f["detail"][:80])
    console.print(table)


@app.command("audit-source")
def mcp_audit_source(
    path: Path = typer.Option(..., "--path", "-p", help="Directory or file holding the MCP server source"),
    out: Path = typer.Option(Path("reports/mcp-source.json"), "--out", "-o"),
) -> None:
    """Audit MCP server source for the STDIO command-injection class.

    Reads source rather than the wire: the weakness is in how the server
    builds its stdio command, which a live scan cannot observe.
    """
    from mas_sentry.protocols.mcp.runtime import run_stdio_source_audit

    if not path.exists():
        raise typer.BadParameter(f"No such path: {path}")
    rows = run_stdio_source_audit(path=path, target_label=str(path), out=out)
    table = Table(title=f"MCP source audit - {path}")
    table.add_column("Check")
    table.add_column("Severity")
    table.add_column("Detail")
    for row in rows:
        table.add_row(row["check"], row["severity"], row["detail"][:80])
    console.print(table)
