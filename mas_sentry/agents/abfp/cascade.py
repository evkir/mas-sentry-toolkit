# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cascade blast-radius over the live agent-topic interaction graph.

Given a rogue or impersonating agent, estimate how far a contamination it
injects could spread through the publish/subscribe topology. The interaction
graph is directed ``agent -[publish]-> topic -[subscribe]-> agent``, so the
downstream reach of an agent is exactly the set of agents reachable from it.

For each source agent we report three nested views:

- topics: the topics the agent publishes into (its direct injection points);
- direct: agents subscribing to those topics (one topic hop away);
- transitive: every agent reachable downstream (the full contamination cone).
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx


@dataclass(frozen=True, slots=True)
class BlastRadius:
    topics: list[str]
    direct: list[str]
    transitive: list[str]
    direct_count: int
    transitive_count: int


def _is_agent(graph: nx.DiGraph, node: str) -> bool:
    return bool(graph.nodes[node].get("kind") == "agent")


def _is_topic(graph: nx.DiGraph, node: str) -> bool:
    return bool(graph.nodes[node].get("kind") == "topic")


def blast_radius(graph: nx.DiGraph, source_agent: str) -> BlastRadius:
    """Compute the downstream contamination reach of ``source_agent``."""
    if source_agent not in graph:
        return BlastRadius([], [], [], 0, 0)

    topics = sorted(t for t in graph.successors(source_agent) if _is_topic(graph, t))

    direct_set: set[str] = set()
    for topic in topics:
        for agent in graph.successors(topic):
            if _is_agent(graph, agent) and agent != source_agent:
                direct_set.add(agent)
    direct = sorted(direct_set)

    descendants = nx.descendants(graph, source_agent)
    transitive = sorted(node for node in descendants if _is_agent(graph, node) and node != source_agent)

    return BlastRadius(
        topics=topics,
        direct=direct,
        transitive=transitive,
        direct_count=len(direct),
        transitive_count=len(transitive),
    )
