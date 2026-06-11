# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from mas_sentry.core.finding import Finding, Severity
from mas_sentry.reporting.markdown import render_markdown
from mas_sentry.reporting.sarif import write_sarif
from mas_sentry.reporting.structured import write_json, write_junit
from mas_sentry.reporting.unified_html import render_unified_html

app = typer.Typer(no_args_is_help=True)
console = Console()

_VALID_FORMATS = {"html", "md", "json", "junit", "sarif"}


@app.command("convert")
def report_convert(
    src: Path = typer.Argument(..., help="JSON findings file produced by a previous scan"),
    fmt: str = typer.Option("html", "--format", "-f", help="html|md|json|junit|sarif"),
    out: Path = typer.Option(..., "--out", "-o"),
    target: str = typer.Option("unknown", "--target"),
) -> None:
    """Convert a findings JSON into a polished report."""
    if fmt not in _VALID_FORMATS:
        raise typer.BadParameter(f"unknown format: {fmt} (valid: {', '.join(sorted(_VALID_FORMATS))})")
    if not src.exists():
        raise typer.BadParameter(f"source file not found: {src}")

    raw = json.loads(src.read_text(encoding="utf-8"))
    items = raw.get("findings", raw) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise typer.BadParameter("expected a JSON array of findings or an object with a 'findings' array")
    findings = [_to_finding(d) for d in items]

    if fmt == "html":
        render_unified_html(findings, target, out)
    elif fmt == "md":
        render_markdown(findings, target, out)
    elif fmt == "json":
        write_json(findings, target, out)
    elif fmt == "junit":
        write_junit(findings, target, out)
    elif fmt == "sarif":
        write_sarif([f.to_dict() for f in findings], out)

    console.print(f"[green]wrote {fmt} -> {out}[/green]")


def _to_sev(s: Any) -> Severity:
    try:
        return Severity(str(s).upper())
    except (ValueError, AttributeError):
        return Severity.INFO


def _to_finding(d: dict[str, Any]) -> Finding:
    return Finding(
        module=d.get("module", "unknown"),
        title=d.get("title", ""),
        detail=d.get("detail", ""),
        severity=_to_sev(d.get("severity", "INFO")),
        target=d.get("target", ""),
        tags=d.get("tags", []),
        evidence=d.get("evidence", {}),
        references=d.get("references", []),
        captured_at=d.get("captured_at", ""),
    )
