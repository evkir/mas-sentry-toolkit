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

from dataclasses import dataclass, field

import networkx as nx


@dataclass(frozen=True, slots=True)
class BlastRadius:
    topics: list[str]
    direct: list[str]
    transitive: list[str]
    direct_count: int
    transitive_count: int
    inferred_direct: list[str] = field(default_factory=list)
    inferred_transitive: list[str] = field(default_factory=list)


def _is_agent(graph: nx.DiGraph, node: str) -> bool:
    return bool(graph.nodes[node].get("kind") == "agent")


def _is_topic(graph: nx.DiGraph, node: str) -> bool:
    return bool(graph.nodes[node].get("kind") == "topic")


def _edge_is_inferred(graph: nx.DiGraph, u: str, v: str) -> bool:
    return bool(graph.edges[u, v].get("kind") == "subscribe-inferred")


def blast_radius(graph: nx.DiGraph, source_agent: str) -> BlastRadius:
    """Compute the downstream contamination reach of ``source_agent``.

    Reach earned through inferred consume edges (kind="subscribe-inferred") is
    reported separately in ``inferred_direct`` / ``inferred_transitive`` so a
    behavioral inference is never presented as an observed subscription. An agent
    reachable both ways is credited as observed.
    """
    if source_agent not in graph:
        return BlastRadius([], [], [], 0, 0)

    topics = sorted(t for t in graph.successors(source_agent) if _is_topic(graph, t))

    direct_set: set[str] = set()
    observed_direct: set[str] = set()
    for topic in topics:
        for agent in graph.successors(topic):
            if _is_agent(graph, agent) and agent != source_agent:
                direct_set.add(agent)
                if not _edge_is_inferred(graph, topic, agent):
                    observed_direct.add(agent)
    direct = sorted(direct_set)

    descendants = nx.descendants(graph, source_agent)
    transitive = sorted(node for node in descendants if _is_agent(graph, node) and node != source_agent)

    # Observed-only reachability: recompute over the graph with inferred edges
    # removed, so an agent reachable both ways is credited as observed.
    observed_edges = [(u, v) for u, v in graph.edges if not _edge_is_inferred(graph, u, v)]
    observed_reach: set[str] = set()
    if observed_edges:
        observed_view = graph.edge_subgraph(observed_edges)
        if source_agent in observed_view:
            observed_reach = nx.descendants(observed_view, source_agent)

    return BlastRadius(
        topics=topics,
        direct=direct,
        transitive=transitive,
        direct_count=len(direct),
        transitive_count=len(transitive),
        inferred_direct=sorted(direct_set - observed_direct),
        inferred_transitive=sorted(a for a in transitive if a not in observed_reach),
    )
