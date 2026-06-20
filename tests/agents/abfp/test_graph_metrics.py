# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for per-agent graph metrics on the topic graph."""

from __future__ import annotations

import networkx as nx

from mas_sentry.agents.abfp.graph_metrics import agent_metrics, all_metrics, graph_summary
from mas_sentry.agents.abfp.topic_graph import TopicGraphBuilder


def _graph() -> nx.DiGraph:
    b = TopicGraphBuilder()
    # agent_a: publishes to two topics, subscribes to one command topic
    b.observe_publish("agent_a", "sensors/temp")
    b.observe_publish("agent_a", "sensors/humidity")
    b.observe_subscribe("agent_a", "cmd/agent_a")
    # agent_b: publishes to a topic shared with agent_a
    b.observe_publish("agent_b", "sensors/temp")
    return b.build()


def test_agent_metrics_degrees_and_topics() -> None:
    m = agent_metrics(_graph(), "agent_a")
    assert m is not None
    assert m.agent_id == "agent_a"
    assert m.pub_degree == 2
    assert m.sub_degree == 1
    assert m.distinct_topics == 3
    assert 0.0 <= m.betweenness <= 1.0
    assert m.eigenvector >= 0.0


def test_agent_metrics_unknown_returns_none() -> None:
    assert agent_metrics(_graph(), "ghost") is None


def test_all_metrics_covers_only_agents() -> None:
    metrics = all_metrics(_graph())
    assert set(metrics) == {"agent_a", "agent_b"}
    assert metrics["agent_b"].pub_degree == 1
    assert metrics["agent_b"].sub_degree == 0


def test_graph_summary_counts() -> None:
    g = _graph()
    s = graph_summary(g)
    assert s["agents"] == 2
    assert s["topics"] == 3
    assert s["edges"] == g.number_of_edges()
