# SPDX-License-Identifier: AGPL-3.0-or-later
import networkx as nx

from mas_sentry.agents.abfp.cascade import BlastRadius, blast_radius


def _g() -> nx.DiGraph:
    g: nx.DiGraph = nx.DiGraph()
    for a in ("A", "B", "C", "D"):
        g.add_node(a, kind="agent")
    for t in ("T1", "T2", "T3"):
        g.add_node(t, kind="topic")
    # A -> T1 -> B (direct); B -> T2 -> C (transitive); D -> T3 (unrelated)
    g.add_edge("A", "T1", kind="publish", weight=1)
    g.add_edge("T1", "B", kind="subscribe", weight=1)
    g.add_edge("B", "T2", kind="publish", weight=1)
    g.add_edge("T2", "C", kind="subscribe", weight=1)
    g.add_edge("D", "T3", kind="publish", weight=1)
    return g


def test_blast_radius_direct_and_transitive():
    br = blast_radius(_g(), "A")
    assert br.topics == ["T1"]
    assert br.direct == ["B"]
    assert br.transitive == ["B", "C"]
    assert br.direct_count == 1
    assert br.transitive_count == 2


def test_blast_radius_leaf_agent_has_no_reach():
    assert blast_radius(_g(), "C") == BlastRadius([], [], [], 0, 0)


def test_blast_radius_unknown_agent():
    assert blast_radius(_g(), "ghost") == BlastRadius([], [], [], 0, 0)


def test_blast_radius_excludes_self_on_cycle():
    g = _g()
    g.add_edge("C", "T1", kind="publish", weight=1)  # C -> T1 closes a cycle back to B
    br = blast_radius(g, "A")
    assert "A" not in br.transitive
    assert "C" in br.transitive


def _g_inferred() -> nx.DiGraph:
    g: nx.DiGraph = nx.DiGraph()
    for a in ("A", "B", "C"):
        g.add_node(a, kind="agent")
    for t in ("T1", "T2"):
        g.add_node(t, kind="topic")
    g.add_edge("A", "T1", kind="publish", weight=1)
    g.add_edge("T1", "B", kind="subscribe-inferred", inferred=True, tier="verbatim", weight=1)
    g.add_edge("B", "T2", kind="publish", weight=1)
    g.add_edge("T2", "C", kind="subscribe-inferred", inferred=True, tier="directive", weight=1)
    return g


def test_blast_radius_marks_inferred_reach() -> None:
    br = blast_radius(_g_inferred(), "A")
    assert br.direct == ["B"]
    assert br.transitive == ["B", "C"]
    assert br.inferred_direct == ["B"]
    assert br.inferred_transitive == ["B", "C"]


def test_blast_radius_observed_reach_not_marked_inferred() -> None:
    br = blast_radius(_g(), "A")
    assert br.inferred_direct == []
    assert br.inferred_transitive == []


def test_blast_radius_observed_path_credited_over_inferred() -> None:
    # B reachable from A via both an observed and an inferred edge -> observed wins.
    g: nx.DiGraph = nx.DiGraph()
    for a in ("A", "B"):
        g.add_node(a, kind="agent")
    for t in ("T1", "T3"):
        g.add_node(t, kind="topic")
    g.add_edge("A", "T1", kind="publish", weight=1)
    g.add_edge("T1", "B", kind="subscribe-inferred", inferred=True, weight=1)
    g.add_edge("A", "T3", kind="publish", weight=1)
    g.add_edge("T3", "B", kind="subscribe", weight=1)
    br = blast_radius(g, "A")
    assert br.direct == ["B"]
    assert br.inferred_direct == []
    assert br.inferred_transitive == []
