# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the injection propagation graph."""

from __future__ import annotations

import networkx as nx

from mas_sentry.agents.abfp.injection_propagation import (
    InjectionEvent,
    build_propagation_graph,
    has_propagation,
    origin_agents,
    propagation_chains,
    propagation_depth,
)


def _ev(agent: str, ts: float, patterns: set[str], phash: str = "") -> InjectionEvent:
    return InjectionEvent(agent_id=agent, topic="t/x", timestamp=ts, patterns=frozenset(patterns), payload_hash=phash)


def test_empty_events_no_graph() -> None:
    g = build_propagation_graph([])
    assert g.number_of_nodes() == 0
    assert not has_propagation(g)
    assert origin_agents(g) == []
    assert propagation_chains(g) == []


def test_single_emitter_node_no_edges() -> None:
    g = build_propagation_graph([_ev("A", 1.0, {"ignore-previous"}, "h1")])
    assert set(g.nodes) == {"A"}
    assert not has_propagation(g)
    assert origin_agents(g) == ["A"]
    assert propagation_depth(g) == {"A": 0}


def test_independent_emitters_no_edges() -> None:
    # Distinct strong patterns, no re-emission -> no propagation between them.
    g = build_propagation_graph([_ev("A", 1.0, {"ignore-previous"}, "h1"), _ev("B", 2.0, {"tool-call-hijack"}, "h2")])
    assert set(g.nodes) == {"A", "B"}
    assert g.number_of_edges() == 0
    assert origin_agents(g) == ["A", "B"]


def test_directive_relay_edge() -> None:
    g = build_propagation_graph([_ev("A", 1.0, {"ignore-previous"}, "h1"), _ev("B", 2.0, {"ignore-previous"}, "h2")])
    assert g.has_edge("A", "B")
    assert g.edges["A", "B"]["tier"] == "directive"
    assert g.edges["A", "B"]["shared"] == ("ignore-previous",)
    assert origin_agents(g) == ["A"]
    assert propagation_depth(g) == {"A": 0, "B": 1}
    assert propagation_chains(g) == [["A", "B"]]


def test_verbatim_relay_outranks_directive() -> None:
    # Same payload hash re-emitted by a distinct agent -> verbatim tier.
    g = build_propagation_graph(
        [_ev("A", 1.0, {"ignore-previous"}, "same"), _ev("B", 2.0, {"ignore-previous"}, "same")]
    )
    assert g.edges["A", "B"]["tier"] == "verbatim"
    assert g.edges["A", "B"]["shared"] == ("same",)


def test_multi_hop_chain_depth() -> None:
    g = build_propagation_graph(
        [
            _ev("A", 1.0, {"tool-call-hijack"}, "h1"),
            _ev("B", 2.0, {"tool-call-hijack"}, "h2"),
            _ev("C", 3.0, {"tool-call-hijack"}, "h3"),
        ]
    )
    assert g.has_edge("A", "B")
    assert g.has_edge("B", "C")
    assert not g.has_edge("A", "C")  # attributed to nearest prior source, not the origin
    assert propagation_depth(g) == {"A": 0, "B": 1, "C": 2}
    assert propagation_chains(g)[0] == ["A", "B", "C"]


def test_cycle_is_dropped_graph_stays_dag() -> None:
    # A -> B, then A re-emits carrying B's pattern; the back-edge B -> A must not
    # close a cycle. Result stays a DAG and depth is computable.
    g = build_propagation_graph(
        [
            _ev("A", 1.0, {"ignore-previous"}, "h1"),
            _ev("B", 2.0, {"ignore-previous"}, "h2"),
            _ev("A", 3.0, {"ignore-previous"}, "h3"),
        ]
    )
    assert nx.is_directed_acyclic_graph(g)
    assert g.has_edge("A", "B")
    assert not g.has_edge("B", "A")
    # depth must not raise on the DAG
    assert propagation_depth(g)["B"] == 1


def test_verbatim_supersedes_on_repeat_pair() -> None:
    # First a directive hop A->B, later a verbatim hop A->B; edge upgrades to
    # verbatim and weight accumulates.
    g = build_propagation_graph(
        [
            _ev("A", 1.0, {"ignore-previous"}, "d1"),
            _ev("B", 2.0, {"ignore-previous"}, "d2"),
            _ev("A", 3.0, {"tool-call-hijack"}, "same"),
            _ev("B", 4.0, {"tool-call-hijack"}, "same"),
        ]
    )
    assert g.edges["A", "B"]["tier"] == "verbatim"
    assert g.edges["A", "B"]["weight"] == 2
