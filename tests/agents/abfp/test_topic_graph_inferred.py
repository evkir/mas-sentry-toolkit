# SPDX-License-Identifier: AGPL-3.0-or-later
"""Inferred consume edges revive cascade blast-radius in a passive graph."""

from __future__ import annotations

from mas_sentry.agents.abfp.cascade import blast_radius
from mas_sentry.agents.abfp.injection_propagation import ConsumeEdge
from mas_sentry.agents.abfp.topic_graph import TopicGraphBuilder


def _ce(topic: str, agent: str, tier: str = "verbatim", weight: int = 1) -> ConsumeEdge:
    return ConsumeEdge(topic=topic, agent=agent, tier=tier, weight=weight, evidence=("h1",))


def test_passive_graph_blast_radius_empty_without_inferred() -> None:
    # Only publishes observed: no topic -> agent edge, so nobody is reachable.
    b = TopicGraphBuilder()
    b.observe_publish("A", "cmd/a")
    g = b.build()
    br = blast_radius(g, "A")
    assert br.topics == ["cmd/a"]
    assert br.direct == []
    assert br.transitive == []


def test_inferred_consume_edge_revives_direct_reach() -> None:
    b = TopicGraphBuilder()
    b.observe_publish("A", "cmd/a")
    b.feed_consume_edges([_ce("cmd/a", "B")])
    g = b.build()
    br = blast_radius(g, "A")
    assert br.direct == ["B"]
    assert br.transitive == ["B"]
    e = g.edges["cmd/a", "B"]
    assert e["kind"] == "subscribe-inferred"
    assert e["inferred"] is True
    assert e["tier"] == "verbatim"


def test_inferred_edges_chain_transitively() -> None:
    # A -> cmd/a ->(inferred) B -> cmd/b ->(inferred) C
    b = TopicGraphBuilder()
    b.observe_publish("A", "cmd/a")
    b.observe_publish("B", "cmd/b")
    b.feed_consume_edges([_ce("cmd/a", "B"), _ce("cmd/b", "C")])
    g = b.build()
    br = blast_radius(g, "A")
    assert br.direct == ["B"]
    assert br.transitive == ["B", "C"]


def test_observed_subscribe_wins_over_inferred() -> None:
    b = TopicGraphBuilder()
    b.observe_publish("A", "cmd/a")
    b.observe_subscribe("B", "cmd/a")
    b.feed_consume_edges([_ce("cmd/a", "B", tier="verbatim", weight=9)])
    g = b.build()
    e = g.edges["cmd/a", "B"]
    assert e["kind"] == "subscribe"
    assert "inferred" not in e
    # Reachability still holds via the observed edge.
    assert blast_radius(g, "A").direct == ["B"]


def test_feed_consume_edges_returns_self_and_dedups_on_build() -> None:
    b = TopicGraphBuilder()
    b.observe_publish("A", "cmd/a")
    ret = b.feed_consume_edges([_ce("cmd/a", "B")]).feed_consume_edges([_ce("cmd/a", "B")])
    assert ret is b
    g = b.build()
    assert g.number_of_edges() == 2  # A->cmd/a publish + cmd/a->B inferred (single)
