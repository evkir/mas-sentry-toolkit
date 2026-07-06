# SPDX-License-Identifier: AGPL-3.0-or-later
"""Topic-graph dimension: who publishes / subscribes to what."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

import networkx as nx

from .observer import MessageEvent

if TYPE_CHECKING:
    from .injection_propagation import ConsumeEdge


@dataclass(slots=True)
class TopicGraphBuilder:
    pub_edges: dict[tuple[str, str], int] = field(default_factory=dict)  # (agent, topic) → count
    sub_edges: dict[tuple[str, str], int] = field(default_factory=dict)
    consume_edges: list[ConsumeEdge] = field(default_factory=list)  # inferred (topic -> agent)

    def observe_publish(self, agent_id: str, topic: str) -> None:
        key = (agent_id, topic)
        self.pub_edges[key] = self.pub_edges.get(key, 0) + 1

    def observe_subscribe(self, agent_id: str, topic_pattern: str) -> None:
        key = (agent_id, topic_pattern)
        self.sub_edges[key] = self.sub_edges.get(key, 0) + 1

    def feed_events(self, events: list[MessageEvent]) -> Self:
        for e in events:
            self.observe_publish(e.agent_id, e.topic)
        return self

    def feed_consume_edges(self, edges: list[ConsumeEdge]) -> Self:
        """Add inferred consume edges (topic -> agent) from re-emission evidence.

        These are behavioral inferences, not observed SUBSCRIBEs; build() marks
        them kind="subscribe-inferred" and never lets one overwrite an observed
        subscribe for the same (topic, agent).
        """
        self.consume_edges.extend(edges)
        return self

    def build(self) -> nx.DiGraph:
        g: nx.DiGraph = nx.DiGraph()
        for (agent, topic), count in self.pub_edges.items():
            g.add_node(agent, kind="agent")
            g.add_node(topic, kind="topic")
            g.add_edge(agent, topic, kind="publish", weight=count)
        for (agent, topic), count in self.sub_edges.items():
            g.add_node(agent, kind="agent")
            g.add_node(topic, kind="topic")
            g.add_edge(topic, agent, kind="subscribe", weight=count)
        for edge in self.consume_edges:
            # Observed subscribe (or an already-added inferred edge) wins; never
            # overwrite ground truth with a behavioral inference.
            if g.has_edge(edge.topic, edge.agent):
                continue
            g.add_node(edge.agent, kind="agent")
            g.add_node(edge.topic, kind="topic")
            g.add_edge(
                edge.topic,
                edge.agent,
                kind="subscribe-inferred",
                weight=edge.weight,
                tier=edge.tier,
                evidence=edge.evidence,
                inferred=True,
            )
        return g
