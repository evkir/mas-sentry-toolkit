# SPDX-License-Identifier: AGPL-3.0-or-later
"""Rogue-agent detector. Maps to OWASP ASI10."""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .graph_diff import GraphDiff, diff_graphs
from .scoring import AnomalyScore, DimensionScore, Severity, compose


@dataclass(frozen=True, slots=True)
class RogueFinding:
    agent_id: str
    score: AnomalyScore
    diff_summary: dict[str, list[str]]
    is_rogue: bool


def detect_rogue(
    baseline_graph: nx.DiGraph,
    current_graph: nx.DiGraph,
    extra_dimensions: dict[str, list[DimensionScore]] | None = None,
) -> list[RogueFinding]:
    diff = diff_graphs(baseline_graph, current_graph)
    extra = extra_dimensions or {}
    findings: list[RogueFinding] = []
    suspects = diff.new_agents | set(diff.new_topics_per_agent.keys())
    for agent_id in suspects:
        topic_raw = _topic_dimension(agent_id, diff)
        dims = [DimensionScore(name="topic", raw=topic_raw, reason=_topic_reason(agent_id, diff))]
        dims.extend(extra.get(agent_id, []))
        score = compose(agent_id, dims)
        findings.append(
            RogueFinding(
                agent_id=agent_id,
                score=score,
                diff_summary=_diff_summary(agent_id, diff),
                is_rogue=score.severity in {Severity.HIGH, Severity.CRITICAL},
            )
        )
    return findings


def _topic_dimension(agent_id: str, diff: GraphDiff) -> float:
    if agent_id in diff.new_agents:
        return 1.0
    new_topics = diff.new_topics_per_agent.get(agent_id, set())
    return min(1.0, 0.3 + len(new_topics) * 0.15)


def _topic_reason(agent_id: str, diff: GraphDiff) -> str:
    if agent_id in diff.new_agents:
        return "Agent absent from baseline (never seen before)"
    nt = diff.new_topics_per_agent.get(agent_id, set())
    return f"Published to {len(nt)} new topic(s): {sorted(nt)[:3]}"


def _diff_summary(agent_id: str, diff: GraphDiff) -> dict[str, list[str]]:
    return {
        "new_topics": sorted(diff.new_topics_per_agent.get(agent_id, set())),
        "removed_topics": sorted(diff.removed_topics_per_agent.get(agent_id, set())),
    }
