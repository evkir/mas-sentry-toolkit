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


def test_abfp_shaped_finding_adapts_to_html(tmp_path: Path):
    src = tmp_path / "abfp.json"
    src.write_text(
        json.dumps(
            {
                "target": "mqtt://demo:1883",
                "findings": [
                    {
                        "agent_id": "agent-7",
                        "total": 82.5,
                        "severity": "HIGH",
                        "diff": "betweenness drift; 2 new topics",
                        "dimensions": [
                            {"name": "timing", "raw": 0.61, "reason": "interval variance 3x"},
                            {"name": "identity", "raw": 0.9, "reason": "client-id mismatch"},
                        ],
                    }
                ],
            }
        )
    )
    out = tmp_path / "out.html"
    r = runner.invoke(
        app, ["report", "convert", str(src), "-f", "html", "-o", str(out), "--target", "mqtt://demo:1883"]
    )
    assert r.exit_code == 0, r.stdout
    html = out.read_text()
    assert "agent-7" in html
    assert "Rogue agent" in html
    assert "betweenness drift" in html
    assert "interval variance 3x" in html
    assert "client-id mismatch" in html


def test_graph_block_renders_centrality(tmp_path: Path):
    src = tmp_path / "g.json"
    src.write_text(
        json.dumps(
            {
                "target": "mqtt://demo:1883",
                "findings": [{"agent_id": "agent-7", "severity": "HIGH", "diff": "drift"}],
                "graph": {
                    "summary": {"agents": 2, "topics": 4, "edges": 6},
                    "agents": {
                        "agent-7": {
                            "agent_id": "agent-7",
                            "pub_degree": 5,
                            "sub_degree": 3,
                            "betweenness": 0.4231,
                            "eigenvector": 0.7102,
                            "distinct_topics": 4,
                        }
                    },
                },
            }
        )
    )
    out = tmp_path / "g.html"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(out), "--target", "demo"])
    assert r.exit_code == 0, r.stdout
    html = out.read_text()
    assert "ABFP Graph Centrality" in html
    assert "agent-7" in html
    assert "0.423" in html
    assert "0.710" in html


def test_no_graph_block_omits_centrality(tmp_path: Path):
    src = tmp_path / "n.json"
    src.write_text(json.dumps({"findings": [{"module": "mcp.ssrf", "title": "SSRF", "severity": "HIGH"}]}))
    out = tmp_path / "n.html"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(out), "--target", "t"])
    assert r.exit_code == 0, r.stdout
    assert "ABFP Graph Centrality" not in out.read_text()


def test_abfp_taxonomy_tags_from_dimensions():
    from mas_sentry.cli.report_cmd import _abfp_taxonomy_tags

    dims = [
        {"name": "burst", "raw": 0.55},
        {"name": "payload", "raw": 0.8},
        {"name": "identity", "raw": 0.9},
        {"name": "timing", "raw": 0.10},  # below threshold -> skipped
    ]
    tags = _abfp_taxonomy_tags(dims)
    assert tags == ["ASI10_Rogue_Agent", "CWE-400", "CWE-290"]  # CWE-400 deduped, CWE-799 omitted


def test_abfp_cwe_badge_in_html_and_sarif(tmp_path: Path):
    src = tmp_path / "f.json"
    src.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "agent_id": "agent-7",
                        "severity": "HIGH",
                        "diff": "drift",
                        "dimensions": [{"name": "identity", "raw": 0.9, "reason": "id mismatch"}],
                    }
                ]
            }
        )
    )
    html = tmp_path / "o.html"
    r1 = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(html), "--target", "t"])
    assert r1.exit_code == 0, r1.stdout
    assert "CWE-290" in html.read_text()

    sarif = tmp_path / "o.sarif"
    r2 = runner.invoke(app, ["report", "convert", str(src), "-f", "sarif", "-o", str(sarif), "--target", "t"])
    assert r2.exit_code == 0, r2.stdout
    doc = json.loads(sarif.read_text())
    assert "CWE-290" in doc["runs"][0]["results"][0]["properties"]["tags"]
