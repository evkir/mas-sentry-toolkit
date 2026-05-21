# SPDX-License-Identifier: AGPL-3.0-or-later
"""Topic-graph dimension: who publishes / subscribes to what."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Self

import networkx as nx

from .observer import MessageEvent


@dataclass(slots=True)
class TopicGraphBuilder:
    pub_edges: dict[tuple[str, str], int] = field(default_factory=dict)  # (agent, topic) → count
    sub_edges: dict[tuple[str, str], int] = field(default_factory=dict)

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
        return g
