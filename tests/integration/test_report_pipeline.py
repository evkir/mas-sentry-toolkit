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
    # CWE pass then STRIDE pass; CWE-400/STRIDE_DoS deduped, timing below threshold omitted
    assert tags == [
        "ASI10_Rogue_Agent",
        "CWE-400",
        "CWE-290",
        "STRIDE_Denial_Of_Service",
        "STRIDE_Spoofing",
    ]


def test_abfp_stride_semantics():
    from mas_sentry.cli.report_cmd import _abfp_taxonomy_tags

    # timing maps to DoS (CWE-799 frequency control), topic to Elevation of Privilege
    tags = _abfp_taxonomy_tags(
        [
            {"name": "timing", "raw": 0.6},
            {"name": "topic", "raw": 0.7},
        ]
    )
    assert "STRIDE_Denial_Of_Service" in tags
    assert "STRIDE_Elevation_Of_Privilege" in tags
    # below-threshold dimensions contribute no STRIDE tag
    assert _abfp_taxonomy_tags([{"name": "identity", "raw": 0.1}]) == ["ASI10_Rogue_Agent"]


def test_abfp_injection_dimension_full_taxonomy():
    from mas_sentry.cli.report_cmd import _abfp_taxonomy_tags

    # A fired injection dimension carries the LLM-prompt-injection lens across
    # all four taxonomies: ASI01 goal hijack, CWE-1427, STRIDE Tampering, ATLAS T0051.
    tags = _abfp_taxonomy_tags([{"name": "injection", "raw": 0.8}])
    assert "ASI10_Rogue_Agent" in tags  # base
    assert "ASI01_Goal_Hijack" in tags
    assert "CWE-1427" in tags
    assert "STRIDE_Tampering" in tags
    assert "AML.T0051" in tags
    # below threshold -> no injection taxonomy leaks through
    assert _abfp_taxonomy_tags([{"name": "injection", "raw": 0.1}]) == ["ASI10_Rogue_Agent"]


def test_abfp_taxonomy_badge_in_html_and_sarif(tmp_path: Path):
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
    # STRIDE parity: identity dimension also yields a Spoofing tag in HTML and SARIF
    assert "STRIDE_Spoofing" in html.read_text()
    assert "tag stride" in html.read_text()
    assert "STRIDE_Spoofing" in doc["runs"][0]["results"][0]["properties"]["tags"]


def test_abfp_injection_badge_end_to_end(tmp_path: Path):
    src = tmp_path / "inj.json"
    src.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "agent_id": "poisoned-relay",
                        "severity": "HIGH",
                        "diff": "ipi",
                        "dimensions": [{"name": "injection", "raw": 0.9, "reason": "ignore-previous in payload"}],
                    }
                ]
            }
        )
    )
    html = tmp_path / "inj.html"
    r1 = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(html), "--target", "t"])
    assert r1.exit_code == 0, r1.stdout
    body = html.read_text()
    assert "CWE-1427" in body
    assert "AML.T0051" in body

    sarif = tmp_path / "inj.sarif"
    r2 = runner.invoke(app, ["report", "convert", str(src), "-f", "sarif", "-o", str(sarif), "--target", "t"])
    assert r2.exit_code == 0, r2.stdout
    assert "AML.T0051" in sarif.read_text()
    doc = json.loads(sarif.read_text())
    assert "CWE-1427" in doc["runs"][0]["results"][0]["properties"]["tags"]


def test_abfp_blast_radius_in_html_and_sarif(tmp_path: Path):
    src = tmp_path / "f.json"
    src.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "agent_id": "rogue-1",
                        "severity": "HIGH",
                        "diff": "drift",
                        "dimensions": [{"name": "topic", "raw": 0.8, "reason": "new topics"}],
                        "blast_radius": {
                            "topics": ["t/a"],
                            "direct": ["sub-1"],
                            "transitive": ["sub-1", "sub-2"],
                            "direct_count": 1,
                            "transitive_count": 2,
                        },
                    }
                ]
            }
        )
    )
    html = tmp_path / "o.html"
    r1 = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(html), "--target", "t"])
    assert r1.exit_code == 0, r1.stdout
    body = html.read_text()
    assert "Cascade blast radius" in body
    assert "transitive 2" in body
    assert "sub-2" in body

    sarif = tmp_path / "o.sarif"
    r2 = runner.invoke(app, ["report", "convert", str(src), "-f", "sarif", "-o", str(sarif), "--target", "t"])
    assert r2.exit_code == 0, r2.stdout
    props = json.loads(sarif.read_text())["runs"][0]["results"][0]["properties"]
    assert props["blast_radius"]["transitive_count"] == 2


def test_propagation_block_flows_into_reports(tmp_path: Path):
    src = tmp_path / "abfp.json"
    src.write_text(
        json.dumps(
            {
                "target": "mqtt://demo:1883",
                "findings": [{"agent_id": "agent-7", "severity": "HIGH", "diff": "drift"}],
                "propagation": [
                    {
                        "target": "planner",
                        "origin": "ingest",
                        "depth": 2,
                        "tier": "verbatim",
                        "chain": ["ingest", "router", "planner"],
                        "severity": "CRITICAL",
                        "tags": ["ASI01_Goal_Hijack", "ASI05_Cascading_Failure"],
                        "blast_radius": {
                            "topics": ["t/x"],
                            "direct": ["worker"],
                            "transitive": ["worker", "logger"],
                            "direct_count": 1,
                            "transitive_count": 2,
                        },
                    }
                ],
            }
        )
    )
    # SARIF: contamination surfaces as its own rule, CRITICAL-banded, tags + blast radius intact
    sarif = tmp_path / "o.sarif"
    r = runner.invoke(
        app, ["report", "convert", str(src), "-f", "sarif", "-o", str(sarif), "--target", "mqtt://demo:1883"]
    )
    assert r.exit_code == 0, r.stdout
    doc = json.loads(sarif.read_text())
    results = doc["runs"][0]["results"]
    prop = [x for x in results if x["ruleId"] == "MAS-SENTRY-ABFP.PROPAGATION"]
    assert prop, "propagation finding missing from SARIF"
    assert "ASI05_Cascading_Failure" in prop[0]["properties"]["tags"]
    assert prop[0]["properties"]["blast_radius"]["transitive_count"] == 2
    rule = next(rr for rr in doc["runs"][0]["tool"]["driver"]["rules"] if rr["id"] == "MAS-SENTRY-ABFP.PROPAGATION")
    assert float(rule["properties"]["security-severity"]) >= 9.0

    # HTML/MD: the chain data reaches the document (distinct rendering lands in a later slice)
    for fmt, ext in [("html", "html"), ("md", "md")]:
        out = tmp_path / f"o.{ext}"
        rr = runner.invoke(app, ["report", "convert", str(src), "-f", fmt, "-o", str(out), "--target", "t"])
        assert rr.exit_code == 0, rr.stdout
        body = out.read_text()
        assert "planner" in body and "ingest" in body


def test_no_propagation_block_is_noop(tmp_path: Path):
    src = tmp_path / "n.json"
    src.write_text(json.dumps({"findings": [{"module": "mcp.ssrf", "title": "SSRF", "severity": "HIGH"}]}))
    out = tmp_path / "n.sarif"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "sarif", "-o", str(out), "--target", "t"])
    assert r.exit_code == 0, r.stdout
    doc = json.loads(out.read_text())
    assert not [x for x in doc["runs"][0]["results"] if x["ruleId"] == "MAS-SENTRY-ABFP.PROPAGATION"]


def test_propagation_chain_renders_distinctly(tmp_path: Path):
    src = tmp_path / "abfp.json"
    src.write_text(
        json.dumps(
            {
                "findings": [],
                "propagation": [
                    {
                        "target": "planner",
                        "origin": "ingest",
                        "depth": 2,
                        "tier": "verbatim",
                        "chain": ["ingest", "router", "planner"],
                        "severity": "CRITICAL",
                        "tags": ["ASI05_Cascading_Failure"],
                        "blast_radius": {
                            "topics": ["t/x"],
                            "direct": ["worker"],
                            "transitive": ["worker", "logger"],
                            "direct_count": 1,
                            "transitive_count": 2,
                        },
                    }
                ],
            }
        )
    )
    # HTML: dedicated chain block, not just the evidence JSON dump
    html = tmp_path / "o.html"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(html), "--target", "t"])
    assert r.exit_code == 0, r.stdout
    body = html.read_text()
    assert "Contamination chain" in body
    assert "ingest -&gt; router -&gt; planner" in body  # autoescaped arrows
    assert 'class="chain-path"' in body

    # MD: human-readable chain line + onward blast radius, above the raw evidence block
    md = tmp_path / "o.md"
    r2 = runner.invoke(app, ["report", "convert", str(src), "-f", "md", "-o", str(md), "--target", "t"])
    assert r2.exit_code == 0, r2.stdout
    text = md.read_text()
    assert "**Contamination chain:** ingest -> router -> planner (depth 2, verbatim)" in text
    assert "**Onward blast radius:** 2 agent(s): worker, logger" in text


def test_propagation_summary_banner(tmp_path: Path):
    src = tmp_path / "abfp.json"
    src.write_text(
        json.dumps(
            {
                "findings": [],
                "propagation": [
                    {
                        "target": "planner",
                        "origin": "ingest",
                        "depth": 2,
                        "tier": "verbatim",
                        "chain": ["ingest", "router", "planner"],
                        "severity": "CRITICAL",
                        "tags": ["ASI05_Cascading_Failure"],
                    }
                ],
                "propagation_summary": {"contaminated": 3, "max_depth": 2, "origins": ["ingest", "seed"]},
            }
        )
    )
    html = tmp_path / "o.html"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(html), "--target", "t"])
    assert r.exit_code == 0, r.stdout
    body = html.read_text()
    assert 'class="prop-summary"' in body
    assert "3 agent(s) contaminated" in body
    assert "max chain depth 2" in body
    assert "ingest, seed" in body

    md = tmp_path / "o.md"
    r2 = runner.invoke(app, ["report", "convert", str(src), "-f", "md", "-o", str(md), "--target", "t"])
    assert r2.exit_code == 0, r2.stdout
    text = md.read_text()
    assert "## Injection Propagation" in text
    assert "- **Contaminated agents:** 3" in text
    assert "- **Max chain depth:** 2" in text
    assert "- **Origin(s):** ingest, seed" in text
    assert text.index("## Injection Propagation") < text.index("## Summary")


def test_no_propagation_summary_omits_banner(tmp_path: Path):
    src = tmp_path / "n.json"
    src.write_text(json.dumps({"findings": [{"module": "mcp.ssrf", "title": "SSRF", "severity": "HIGH"}]}))
    html = tmp_path / "n.html"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(html), "--target", "t"])
    assert r.exit_code == 0, r.stdout
    assert 'class="prop-summary"' not in html.read_text()
    md = tmp_path / "n.md"
    r2 = runner.invoke(app, ["report", "convert", str(src), "-f", "md", "-o", str(md), "--target", "t"])
    assert r2.exit_code == 0, r2.stdout
    assert "## Injection Propagation" not in md.read_text()
