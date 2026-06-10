# SPDX-License-Identifier: AGPL-3.0-or-later
"""Markdown report - readable in issue trackers and bug-bounty submissions."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from mas_sentry.core.finding import Finding

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def render_markdown(findings: list[Finding], target: str, out_path: Path) -> None:
    counts = Counter(f.severity.value for f in findings)
    breakdown = " - ".join(f"{sev}: {counts.get(sev, 0)}" for sev in _SEV_ORDER)
    lines: list[str] = [
        f"# MAS-Sentry Audit - {target}",
        "",
        f"**Generated:** {datetime.now(UTC).isoformat(timespec='seconds')}  ",
        f"**Findings:** {len(findings)}  ",
        f"**Breakdown:** {breakdown}",
        "",
        "## Summary",
        "",
        "| # | Severity | Module | Title |",
        "|---|----------|--------|-------|",
    ]
    for i, f in enumerate(findings, 1):
        lines.append(f"| {i} | {f.severity.value} | `{f.module}` | {f.title} |")
    lines.extend(["", "## Detail", ""])
    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. {f.title}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity.value}")
        lines.append(f"- **Module:** `{f.module}`")
        lines.append(f"- **Target:** `{f.target}`")
        if f.tags:
            tag_str = ", ".join("`" + t + "`" for t in f.tags)
            lines.append(f"- **Tags:** {tag_str}")
        if f.references:
            lines.append(f"- **References:** {', '.join(f.references)}")
        lines.append("")
        lines.append(f.detail)
        if f.evidence:
            lines.append("")
            lines.append("**Evidence:**")
            lines.append("```json")
            lines.append(json.dumps(f.evidence, indent=2, default=str))
            lines.append("```")
        lines.append("")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
