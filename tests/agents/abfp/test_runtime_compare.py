# SPDX-License-Identifier: AGPL-3.0-or-later
"""compare-mode: a prior snapshot revives rogue drift detection."""

from __future__ import annotations

from pathlib import Path

import networkx as nx

from mas_sentry.agents.abfp.rogue import detect_rogue
from mas_sentry.agents.abfp.runtime import _load_baseline
from mas_sentry.agents.abfp.snapshot import ScanSnapshot
from mas_sentry.agents.abfp.topic_graph import TopicGraphBuilder


def _build(*pubs: tuple[str, str]) -> nx.DiGraph:
    b = TopicGraphBuilder()
    for agent, topic in pubs:
        b.observe_publish(agent, topic)
    return b.build()


def test_load_baseline_none_without_path() -> None:
    assert _load_baseline(None) is None


def test_load_baseline_missing_file_is_none(tmp_path: Path) -> None:
    assert _load_baseline(tmp_path / "nope.json") is None


def test_prior_snapshot_revives_rogue_drift(tmp_path: Path) -> None:
    baseline_graph = _build(("agent_a", "sensors/temp"))
    path = tmp_path / "baseline.json"
    ScanSnapshot(target="mqtt://x", graph=baseline_graph, agents={}).save(path)

    current = _build(
        ("agent_a", "sensors/temp"),
        ("agent_a", "actuators/valve"),
        ("agent_b", "sensors/temp"),
    )
    baseline = _load_baseline(path)
    assert baseline is not None
    findings = detect_rogue(baseline_graph=baseline.graph, current_graph=current)

    by_agent = {f.agent_id: f for f in findings}
    assert "agent_b" in by_agent
    assert by_agent["agent_b"].is_rogue
    # Without the baseline (same-graph) nothing fires -> proves the snapshot is what revives it.
    assert detect_rogue(baseline_graph=current, current_graph=current) == []
