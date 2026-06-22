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
