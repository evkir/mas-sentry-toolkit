# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression: _write_report must serialise slotted BaselineStatus (no __dict__)."""

import json
from pathlib import Path

from mas_sentry.agents.abfp.baseline import BaselineStatus
from mas_sentry.agents.abfp.runtime import _write_report


def test_write_report_serializes_slotted_baseline(tmp_path: Path):
    out = tmp_path / "abfp.json"
    statuses = [
        BaselineStatus(agent_id="agent_a", observed=3, threshold=5, ready=False),
        BaselineStatus(agent_id="agent_b", observed=5, threshold=5, ready=True),
    ]
    _write_report(out, [], statuses, target="lab")
    data = json.loads(out.read_text())
    assert data["target"] == "lab"
    assert data["findings"] == []
    assert data["baseline"][0] == {"agent_id": "agent_a", "observed": 3, "threshold": 5, "ready": False}
    assert data["baseline"][1]["ready"] is True


def test_write_report_includes_graph_block(tmp_path: Path) -> None:
    out = tmp_path / "abfp.json"
    graph = {
        "summary": {"agents": 1, "topics": 2, "edges": 2},
        "agents": {"agent_a": {"pub_degree": 2, "sub_degree": 0}},
    }
    _write_report(out, [], [], target="lab", graph=graph)
    data = json.loads(out.read_text())
    assert data["graph"]["summary"]["agents"] == 1
    assert data["graph"]["agents"]["agent_a"]["pub_degree"] == 2


def test_write_report_omits_graph_when_none(tmp_path: Path) -> None:
    out = tmp_path / "abfp.json"
    _write_report(out, [], [], target="lab")
    data = json.loads(out.read_text())
    assert "graph" not in data


def test_write_report_emits_finding_dimensions(tmp_path: Path) -> None:
    from mas_sentry.agents.abfp.rogue import RogueFinding
    from mas_sentry.agents.abfp.scoring import DimensionScore, compose

    score = compose("agent_a", [DimensionScore(name="identity", raw=0.6, reason="divergent fingerprint")])
    finding = RogueFinding(
        agent_id="agent_a",
        score=score,
        diff_summary={"new_topics": [], "removed_topics": []},
        is_rogue=False,
    )
    out = tmp_path / "abfp.json"
    _write_report(out, [finding], [], target="lab")
    dims = json.loads(out.read_text())["findings"][0]["dimensions"]
    assert {"name": "identity", "raw": 0.6, "reason": "divergent fingerprint"} in dims


def test_write_report_injects_blast_radius(tmp_path: Path) -> None:
    from mas_sentry.agents.abfp.cascade import BlastRadius
    from mas_sentry.agents.abfp.rogue import RogueFinding
    from mas_sentry.agents.abfp.scoring import DimensionScore, compose

    score = compose("agent_a", [DimensionScore(name="topic", raw=1.0, reason="new agent")])
    finding = RogueFinding(agent_id="agent_a", score=score, diff_summary={}, is_rogue=True)
    cascade = {
        "agent_a": BlastRadius(
            topics=["t/x"], direct=["agent_b"], transitive=["agent_b", "agent_c"], direct_count=1, transitive_count=2
        )
    }
    out = tmp_path / "abfp.json"
    _write_report(out, [finding], [], target="lab", cascade=cascade)
    br = json.loads(out.read_text())["findings"][0]["blast_radius"]
    assert br["direct"] == ["agent_b"]
    assert br["transitive_count"] == 2


def test_write_report_blast_radius_null_without_cascade(tmp_path: Path) -> None:
    from mas_sentry.agents.abfp.rogue import RogueFinding
    from mas_sentry.agents.abfp.scoring import DimensionScore, compose

    score = compose("agent_a", [DimensionScore(name="topic", raw=0.5, reason="x")])
    finding = RogueFinding(agent_id="agent_a", score=score, diff_summary={}, is_rogue=False)
    out = tmp_path / "abfp.json"
    _write_report(out, [finding], [], target="lab")
    assert json.loads(out.read_text())["findings"][0]["blast_radius"] is None


def test_write_report_includes_propagation_block(tmp_path: Path) -> None:
    from mas_sentry.agents.abfp.cascade import BlastRadius
    from mas_sentry.agents.abfp.injection_propagation import PropagationFinding
    from mas_sentry.agents.abfp.scoring import Severity

    prop = [
        PropagationFinding(
            target="C", origin="A", depth=2, tier="verbatim", chain=["A", "B", "C"], severity=Severity.CRITICAL
        ),
        PropagationFinding(target="B", origin="A", depth=1, tier="directive", chain=["A", "B"], severity=Severity.HIGH),
    ]
    cascade = {"C": BlastRadius(topics=["t/x"], direct=["D"], transitive=["D"], direct_count=1, transitive_count=1)}
    out = tmp_path / "abfp.json"
    _write_report(out, [], [], target="lab", cascade=cascade, propagation=prop)
    data = json.loads(out.read_text())

    block = data["propagation"]
    assert [e["target"] for e in block] == ["C", "B"]
    crit = block[0]
    assert crit["severity"] == "CRITICAL"
    assert crit["chain"] == ["A", "B", "C"]
    assert "ASI08_Cascading_Failure" in crit["tags"]
    assert crit["blast_radius"]["direct"] == ["D"]  # onward cascade fused in
    assert block[1]["blast_radius"] is None  # B not in cascade map

    summary = data["propagation_summary"]
    assert summary["contaminated"] == 2
    assert summary["max_depth"] == 2
    assert summary["origins"] == ["A"]


def test_write_report_omits_propagation_when_empty(tmp_path: Path) -> None:
    out = tmp_path / "abfp.json"
    _write_report(out, [], [], target="lab", propagation=[])
    data = json.loads(out.read_text())
    assert "propagation" not in data
    assert "propagation_summary" not in data
