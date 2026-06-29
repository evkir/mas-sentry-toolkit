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
    graph = raw.get("graph") if isinstance(raw, dict) else None

    if fmt == "html":
        render_unified_html(findings, target, out, graph=graph)
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


_DIMENSION_CWE = {
    "identity": "CWE-290",  # Authentication Bypass by Spoofing
    "burst": "CWE-400",  # Uncontrolled Resource Consumption
    "payload": "CWE-400",  # Uncontrolled Resource Consumption
    "timing": "CWE-799",  # Improper Control of Interaction Frequency
    "topic": "CWE-269",  # Improper Privilege Management
}
_TAG_FIRE_THRESHOLD = 0.3
_DIMENSION_STRIDE = {
    "identity": "STRIDE_Spoofing",
    "topic": "STRIDE_Elevation_Of_Privilege",
    "payload": "STRIDE_Denial_Of_Service",
    "burst": "STRIDE_Denial_Of_Service",
    "timing": "STRIDE_Denial_Of_Service",
}


def _abfp_taxonomy_tags(dimensions: list[dict[str, Any]]) -> list[str]:
    """Derive ASI/CWE/STRIDE tags from the scoring dimensions that meaningfully fired."""
    tags = ["ASI10_Rogue_Agent"]
    fired = [d for d in dimensions if float(d.get("raw", 0.0)) >= _TAG_FIRE_THRESHOLD]
    for dim in fired:
        cwe = _DIMENSION_CWE.get(str(dim.get("name", "")))
        if cwe and cwe not in tags:
            tags.append(cwe)
    for dim in fired:
        stride = _DIMENSION_STRIDE.get(str(dim.get("name", "")))
        if stride and stride not in tags:
            tags.append(stride)
    return tags


def _abfp_to_finding(d: dict[str, Any]) -> Finding:
    """Adapt an ABFP rogue-scan finding (agent_id/diff/dimensions) to a canonical Finding."""
    agent_id = str(d.get("agent_id", "?"))
    evidence: dict[str, Any] = {"agent_id": agent_id, "total": d.get("total")}
    dims = d.get("dimensions")
    if dims:
        evidence["dimensions"] = dims
    bl = d.get("blast_radius")
    if bl:
        evidence["blast_radius"] = bl
    return Finding(
        module="abfp.rogue",
        title=f"Rogue agent: {agent_id}",
        detail=str(d.get("diff", "")),
        severity=_to_sev(d.get("severity", "INFO")),
        target=str(d.get("target", "")),
        tags=_abfp_taxonomy_tags(dims or []),
        evidence=evidence,
        references=[],
        captured_at=str(d.get("captured_at", "")),
    )


def _to_finding(d: dict[str, Any]) -> Finding:
    if "agent_id" in d and "module" not in d:
        return _abfp_to_finding(d)
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
