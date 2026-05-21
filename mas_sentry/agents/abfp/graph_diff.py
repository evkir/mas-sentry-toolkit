# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detect behavioral drift between two snapshots of a topic graph."""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx


@dataclass(frozen=True, slots=True)
class GraphDiff:
    new_agents: set[str] = field(default_factory=set)
    removed_agents: set[str] = field(default_factory=set)
    new_topics_per_agent: dict[str, set[str]] = field(default_factory=dict)
    removed_topics_per_agent: dict[str, set[str]] = field(default_factory=dict)

    @property
    def has_drift(self) -> bool:
        return bool(
            self.new_agents
            or self.removed_agents
            or any(self.new_topics_per_agent.values())
            or any(self.removed_topics_per_agent.values())
        )


def diff_graphs(baseline: nx.DiGraph, current: nx.DiGraph) -> GraphDiff:
    base_agents = {n for n, a in baseline.nodes(data=True) if a.get("kind") == "agent"}
    cur_agents = {n for n, a in current.nodes(data=True) if a.get("kind") == "agent"}
    new_agents = cur_agents - base_agents
    removed_agents = base_agents - cur_agents

    new_topics: dict[str, set[str]] = {}
    removed_topics: dict[str, set[str]] = {}
    for a in base_agents & cur_agents:
        base_pubs = _publish_targets(baseline, a)
        cur_pubs = _publish_targets(current, a)
        nt = cur_pubs - base_pubs
        rt = base_pubs - cur_pubs
        if nt:
            new_topics[a] = nt
        if rt:
            removed_topics[a] = rt
    return GraphDiff(
        new_agents=new_agents,
        removed_agents=removed_agents,
        new_topics_per_agent=new_topics,
        removed_topics_per_agent=removed_topics,
    )


def _publish_targets(g: nx.DiGraph, agent: str) -> set[str]:
    return {v for _, v, d in g.out_edges(agent, data=True) if d.get("kind") == "publish"}
