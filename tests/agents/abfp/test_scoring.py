# SPDX-License-Identifier: AGPL-3.0-or-later
import networkx as nx

from mas_sentry.agents.abfp.rogue import detect_rogue
from mas_sentry.agents.abfp.scoring import DimensionScore, Severity, compose


def test_scoring_single_dimension_normalizes_to_full_scale():
    # One dimension at raw=1.0 normalizes against its own weight only -> 100.
    s = compose("a", [DimensionScore("topic", 1.0)])
    assert s.total == 100
    assert s.severity == Severity.CRITICAL


def test_scoring_partial_raw_maps_to_mid_severity():
    # raw=0.5 on a single dimension -> 50 -> MEDIUM.
    s = compose("a", [DimensionScore("topic", 0.5)])
    assert s.total == 50
    assert s.severity == Severity.MEDIUM


def test_scoring_critical_when_all_dimensions_max():
    dims = [DimensionScore(n, 1.0) for n in ("timing", "payload", "topic", "identity")]
    s = compose("a", dims)
    assert s.total == 100
    assert s.severity == Severity.CRITICAL


def test_scoring_info_when_no_dimensions():
    s = compose("a", [])
    assert s.total == 0
    assert s.severity == Severity.INFO


def test_rogue_detector_flags_brand_new_agent():
    baseline = nx.DiGraph()
    baseline.add_node("known", kind="agent")
    baseline.add_node("t1", kind="topic")
    baseline.add_edge("known", "t1", kind="publish", weight=10)

    current = baseline.copy()
    current.add_node("intruder", kind="agent")
    current.add_node("t2", kind="topic")
    current.add_edge("intruder", "t2", kind="publish", weight=5)

    findings = detect_rogue(baseline, current)
    agents = {f.agent_id: f for f in findings}
    assert "intruder" in agents
    assert agents["intruder"].is_rogue
    assert agents["intruder"].score.severity == Severity.CRITICAL


def test_rogue_detector_flags_topic_escalation():
    baseline = nx.DiGraph()
    baseline.add_node("agent1", kind="agent")
    baseline.add_node("t1", kind="topic")
    baseline.add_edge("agent1", "t1", kind="publish", weight=10)

    current = baseline.copy()
    current.add_node("t2", kind="topic")
    current.add_node("t3", kind="topic")
    current.add_edge("agent1", "t2", kind="publish", weight=5)
    current.add_edge("agent1", "t3", kind="publish", weight=5)

    findings = detect_rogue(baseline, current)
    assert any(f.agent_id == "agent1" for f in findings)
