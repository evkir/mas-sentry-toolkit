# SPDX-License-Identifier: AGPL-3.0-or-later
"""Centrality + degree metrics per agent on the topic graph."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import networkx as nx


@dataclass(frozen=True, slots=True)
class AgentGraphMetrics:
    agent_id: str
    pub_degree: int
    sub_degree: int
    betweenness: float
    eigenvector: float
    distinct_topics: int


def agent_metrics(g: nx.DiGraph, agent_id: str) -> AgentGraphMetrics | None:
    if agent_id not in g:
        return None
    out_edges = [(u, v, d) for u, v, d in g.out_edges(agent_id, data=True) if d.get("kind") == "publish"]
    in_edges = [(u, v, d) for u, v, d in g.in_edges(agent_id, data=True) if d.get("kind") == "subscribe"]
    try:
        bc = nx.betweenness_centrality(g).get(agent_id, 0.0)
    except Exception:
        bc = 0.0
    try:
        ec = nx.eigenvector_centrality_numpy(g, max_iter=200).get(agent_id, 0.0)
    except Exception:
        ec = 0.0
    return AgentGraphMetrics(
        agent_id=agent_id,
        pub_degree=len(out_edges),
        sub_degree=len(in_edges),
        betweenness=float(bc),
        eigenvector=float(ec),
        distinct_topics=len({v for _, v, _ in out_edges} | {u for u, _, _ in in_edges}),
    )


def all_metrics(g: nx.DiGraph) -> dict[str, AgentGraphMetrics]:
    out: dict[str, AgentGraphMetrics] = {}
    for n, attrs in g.nodes(data=True):
        if attrs.get("kind") == "agent":
            m = agent_metrics(g, n)
            if m:
                out[n] = m
    return out


def graph_summary(g: nx.DiGraph) -> dict[str, Any]:
    agents = [n for n, a in g.nodes(data=True) if a.get("kind") == "agent"]
    topics = [n for n, a in g.nodes(data=True) if a.get("kind") == "topic"]
    return {"agents": len(agents), "topics": len(topics), "edges": g.number_of_edges()}
