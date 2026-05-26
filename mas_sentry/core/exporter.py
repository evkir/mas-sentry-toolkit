# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from datetime import datetime
from pathlib import Path
from typing import Any


class ReportExporter:
    def __init__(self, output_dir: str = "reports/output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def to_json(self, summary: dict[str, Any], findings: list[dict[str, Any]], filename: str | None = None) -> Path:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = filename or f"report_{summary.get('session_id', 'unknown')}_{ts}.json"
        path = self.output_dir / fname

        report = {
            "meta": {
                "tool": "MAS-Sentry-Toolkit",
                "version": "0.1.0",
                "generated_at": datetime.utcnow().isoformat() + "Z",
            },
            "session": summary,
            "findings": findings,
            "statistics": self._compute_stats(findings),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return path

    def to_markdown(self, summary: dict[str, Any], findings: list[dict[str, Any]], filename: str | None = None) -> Path:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = filename or f"report_{summary.get('session_id', 'unknown')}_{ts}.md"
        path = self.output_dir / fname

        stats = self._compute_stats(findings)
        lines = [
            "# MAS-Sentry-Toolkit — Security Audit Report",
            "",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"**Target:** `{summary.get('target', 'N/A')}`",
            f"**Protocol:** `{summary.get('protocol', 'N/A')}`",
            "",
            "## Executive Summary",
            "",
            f"Total findings: **{len(findings)}**",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {stats['by_severity'].get(sev, 0)} |")

        lines += ["", "## Findings", ""]

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for f in sorted(findings, key=lambda x: sev_order.get(x.get("severity", "INFO").upper(), 99)):
            sev = f.get("severity", "INFO").upper()
            lines += [
                f"### [{sev}] {f.get('title', 'Untitled')}",
                "",
                f"**Severity:** `{sev}`",
                f"**Timestamp:** {f.get('timestamp', 'N/A')}",
                "",
                f"{f.get('description', 'No description.')}",
                "",
                "---",
                "",
            ]

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

        return path

    @staticmethod
    def _compute_stats(findings: list[dict[str, Any]]) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "critical_or_high": by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0),
        }
