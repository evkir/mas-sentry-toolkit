# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from pathlib import Path

from typer.testing import CliRunner

from mas_sentry.cli import app

runner = CliRunner()


def test_pipeline_json_to_all_formats(tmp_path: Path):
    findings_json = tmp_path / "findings.json"
    findings_json.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "module": "mcp.ssrf",
                        "title": "SSRF",
                        "detail": "IMDS reachable",
                        "severity": "CRITICAL",
                        "target": "lab",
                        "tags": ["ASI02_Tool_Misuse", "CWE-918"],
                    },
                    {
                        "module": "abfp.rogue",
                        "title": "Rogue agent",
                        "detail": "unknown id",
                        "severity": "HIGH",
                        "target": "lab",
                        "tags": ["ASI10_Rogue_Agent"],
                    },
                ],
            }
        )
    )
    for fmt, ext in [("html", "html"), ("md", "md"), ("json", "json"), ("junit", "xml"), ("sarif", "sarif.json")]:
        out = tmp_path / f"report.{ext}"
        r = runner.invoke(app, ["report", "convert", str(findings_json), "-f", fmt, "-o", str(out), "--target", "lab"])
        assert r.exit_code == 0, f"{fmt} failed: {r.stdout}"
        assert out.exists() and out.stat().st_size > 0
