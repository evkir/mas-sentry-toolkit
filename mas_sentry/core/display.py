# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white",
}

SEVERITY_ICONS = {
    "CRITICAL": "💀",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️ ",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def severity_text(severity: str) -> Text:
    color = SEVERITY_COLORS.get(severity.upper(), "white")
    icon = SEVERITY_ICONS.get(severity.upper(), "  ")
    return Text(f"{icon} {severity}", style=color)


def print_finding(finding: dict[str, Any]) -> None:
    sev = finding.get("severity", "INFO").upper()
    color = SEVERITY_COLORS.get(sev, "white")
    icon = SEVERITY_ICONS.get(sev, "  ")
    title = f"{icon}  [{color}]{sev}[/{color}] — {finding.get('title', 'Unknown')}"
    body = (
        f"[bold]Description:[/bold] {finding.get('description', 'N/A')}\n"
        f"[bold]ID:[/bold] {finding.get('id', '?')}  "
        f"[bold]Timestamp:[/bold] {finding.get('timestamp', 'N/A')}"
    )
    console.print(Panel(body, title=title, border_style=color, expand=False))


def print_findings_table(findings: list[dict[str, Any]]) -> None:
    if not findings:
        console.print("[green][+] No findings to display.[/green]")
        return

    table = Table(title="📋 Scan Findings", box=box.ROUNDED, show_lines=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=12)
    table.add_column("Title", style="bold")
    table.add_column("Description")
    table.add_column("Timestamp", width=22, style="dim")

    def sev_key(f):
        s = f.get("severity", "INFO").upper()
        return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 99

    for f in sorted(findings, key=sev_key):
        sev = f.get("severity", "INFO").upper()
        color = SEVERITY_COLORS.get(sev, "white")
        icon = SEVERITY_ICONS.get(sev, "  ")
        table.add_row(
            str(f.get("id", "?")),
            Text(f"{icon} {sev}", style=color),
            f.get("title", "N/A"),
            f.get("description", "N/A")[:80],
            f.get("timestamp", "N/A"),
        )
    console.print(table)


def print_summary_panel(summary: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1

    breakdown = "  ".join(
        f"[{SEVERITY_COLORS[s]}]{SEVERITY_ICONS[s]} {s}: {counts[s]}[/{SEVERITY_COLORS[s]}]" for s in SEVERITY_ORDER
    )
    body = (
        f"[bold]Session ID:[/bold]  {summary.get('session_id', 'N/A')}\n"
        f"[bold]Target:[/bold]      {summary.get('target', 'N/A')}\n"
        f"[bold]Protocol:[/bold]    {summary.get('protocol', 'N/A')}\n"
        f"[bold]Duration:[/bold]    {summary.get('duration_seconds', 0)}s\n\n"
        f"{breakdown}"
    )
    console.print(Panel(body, title="📊 Session Summary", border_style="bold blue"))
