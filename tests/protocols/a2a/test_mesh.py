# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mas_sentry.core.finding import Severity
from mas_sentry.protocols.a2a.client import AgentCard
from mas_sentry.protocols.a2a.mesh import (
    MeshAgent,
    agent_scopes,
    build_delegation_graph,
    detect_delegation_cycles,
    detect_scope_escalation,
    load_mesh_manifest,
)

TARGET = "mesh://lab"


def _agent(aid: str, *scopes: str) -> MeshAgent:
    return MeshAgent(id=aid, url=f"https://{aid}.local", scopes=frozenset(scopes))


def _graph(agents: list[MeshAgent], edges: list[tuple[str, str]]):
    return build_delegation_graph(agents, edges)


# --- agent_scopes: reuse of card_audit extractors ---


def test_agent_scopes_union_across_schemes() -> None:
    card = AgentCard(
        name="a",
        description="",
        url="",
        raw={
            "securitySchemes": {
                "o1": {"type": "oauth2", "flows": {"authorizationCode": {"scopes": {"read:tasks": ""}}}},
                "o2": {"oauth2SecurityScheme": {"flows": {"clientCredentials": {"scopes": {"write:tasks": ""}}}}},
            }
        },
    )
    assert agent_scopes(card) == frozenset({"read:tasks", "write:tasks"})


def test_agent_scopes_empty_when_no_schemes() -> None:
    assert agent_scopes(AgentCard(name="a", description="", url="", raw={})) == frozenset()


# --- detection: the vertical slice ---


def test_attenuating_hop_no_finding() -> None:
    # A holds read+write, delegates to B holding only read: proper attenuation.
    g = _graph([_agent("A", "read", "write"), _agent("B", "read")], [("A", "B")])
    assert detect_scope_escalation(g, TARGET) == []


def test_equal_scopes_no_finding() -> None:
    g = _graph([_agent("A", "read"), _agent("B", "read")], [("A", "B")])
    assert detect_scope_escalation(g, TARGET) == []


def test_first_hop_escalation_is_high() -> None:
    # A delegates to B which additionally holds admin: non-attenuating, depth 1.
    g = _graph([_agent("A", "read"), _agent("B", "read", "admin")], [("A", "B")])
    out = detect_scope_escalation(g, TARGET)
    assert len(out) == 1
    f = out[0]
    assert f.severity is Severity.HIGH
    assert f.module == "a2a.mesh.priv_esc"
    assert f.evidence["gained_scopes"] == ["admin"]
    assert f.evidence["chain_depth"] == 1
    assert f.evidence["delegation_chain"] == ["A", "B"]
    assert "CWE-269" in f.tags


def test_transitive_escalation_is_critical() -> None:
    # A -> B attenuated (both read); B -> C widens to admin at depth 2.
    g = _graph(
        [_agent("A", "read"), _agent("B", "read"), _agent("C", "read", "admin")],
        [("A", "B"), ("B", "C")],
    )
    out = detect_scope_escalation(g, TARGET)
    assert len(out) == 1
    f = out[0]
    assert f.severity is Severity.CRITICAL
    assert f.evidence["chain_depth"] == 2
    assert f.evidence["delegation_chain"] == ["A", "B", "C"]
    assert f.evidence["gained_scopes"] == ["admin"]


def test_multiple_findings_sorted_worst_first() -> None:
    # One HIGH first-hop widening and one CRITICAL depth-2 widening.
    g = _graph(
        [_agent("A", "read"), _agent("B", "read", "x"), _agent("C", "read", "x", "y")],
        [("A", "B"), ("B", "C")],
    )
    out = detect_scope_escalation(g, TARGET)
    assert [f.severity for f in out] == [Severity.CRITICAL, Severity.HIGH]
    assert out[0].evidence["delegate"] == "C"
    assert out[1].evidence["delegate"] == "B"


def test_cycle_is_finite_and_detected() -> None:
    # A <-> B cycle: B widens over A. Detection terminates and flags the widening edge.
    g = _graph([_agent("A", "read"), _agent("B", "read", "admin")], [("A", "B"), ("B", "A")])
    out = detect_scope_escalation(g, TARGET)
    delegates = sorted(f.evidence["delegate"] for f in out)
    assert delegates == ["B"]  # A -> B widens; B -> A attenuates


# --- manifest loading + validation ---


def _write(tmp_path: Path, obj: object) -> Path:
    p = tmp_path / "mesh.json"
    p.write_text(json.dumps(obj))
    return p


def test_load_manifest_valid(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {
            "agents": [{"id": "A", "url": "https://a.local"}, {"id": "B", "url": "http://b.local"}],
            "edges": [["A", "B"]],
        },
    )
    agents, edges = load_mesh_manifest(p)
    assert agents == [{"id": "A", "url": "https://a.local"}, {"id": "B", "url": "http://b.local"}]
    assert edges == [("A", "B")]


def test_load_manifest_edges_optional(tmp_path: Path) -> None:
    p = _write(tmp_path, {"agents": [{"id": "A", "url": "https://a.local"}]})
    agents, edges = load_mesh_manifest(p)
    assert agents == [{"id": "A", "url": "https://a.local"}]
    assert edges == []


def test_load_manifest_rejects_undeclared_edge(tmp_path: Path) -> None:
    p = _write(tmp_path, {"agents": [{"id": "A", "url": "https://a.local"}], "edges": [["A", "Z"]]})
    with pytest.raises(ValueError, match="undeclared agent"):
        load_mesh_manifest(p)


def test_load_manifest_rejects_duplicate_id(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {"agents": [{"id": "A", "url": "https://a.local"}, {"id": "A", "url": "https://a2.local"}]},
    )
    with pytest.raises(ValueError, match="duplicate agent id"):
        load_mesh_manifest(p)


def test_load_manifest_rejects_non_http_url(tmp_path: Path) -> None:
    p = _write(tmp_path, {"agents": [{"id": "A", "url": "ftp://a.local"}]})
    with pytest.raises(ValueError, match="http"):
        load_mesh_manifest(p)


def test_load_manifest_rejects_bad_edge_shape(tmp_path: Path) -> None:
    p = _write(tmp_path, {"agents": [{"id": "A", "url": "https://a.local"}], "edges": [["A"]]})
    with pytest.raises(ValueError, match="from, to"):
        load_mesh_manifest(p)


def test_load_manifest_rejects_empty_agents(tmp_path: Path) -> None:
    p = _write(tmp_path, {"agents": []})
    with pytest.raises(ValueError, match="non-empty agents"):
        load_mesh_manifest(p)


def test_load_manifest_rejects_non_object(tmp_path: Path) -> None:
    p = _write(tmp_path, ["not", "an", "object"])
    with pytest.raises(ValueError, match="JSON object"):
        load_mesh_manifest(p)


def test_load_manifest_rejects_edges_not_list(tmp_path: Path) -> None:
    p = _write(tmp_path, {"agents": [{"id": "A", "url": "https://a.local"}], "edges": "A,B"})
    with pytest.raises(ValueError, match="edges must be a list"):
        load_mesh_manifest(p)


def test_load_manifest_rejects_agent_missing_fields(tmp_path: Path) -> None:
    p = _write(tmp_path, {"agents": [{"id": "A"}]})
    with pytest.raises(ValueError, match="id and url"):
        load_mesh_manifest(p)


# --- delegation cycles: recursive-DoS tenant ---


def test_no_cycle_no_finding() -> None:
    g = _graph([_agent("A"), _agent("B")], [("A", "B")])
    assert detect_delegation_cycles(g, TARGET) == []


def test_two_cycle_is_high() -> None:
    g = _graph([_agent("A"), _agent("B")], [("A", "B"), ("B", "A")])
    out = detect_delegation_cycles(g, TARGET)
    assert len(out) == 1
    f = out[0]
    assert f.severity is Severity.HIGH
    assert f.module == "a2a.mesh.delegation_cycle"
    assert f.evidence["cycle"] == ["A", "B"]
    assert f.evidence["length"] == 2
    assert "CWE-674" in f.tags
    assert "MST_Resource_Exhaustion" in f.tags


def test_self_loop_is_medium() -> None:
    g = _graph([_agent("A")], [("A", "A")])
    out = detect_delegation_cycles(g, TARGET)
    assert len(out) == 1
    assert out[0].severity is Severity.MEDIUM
    assert out[0].evidence["cycle"] == ["A"]
    assert out[0].evidence["length"] == 1


def test_cycle_normalized_to_min_node() -> None:
    # C -> A -> B -> C is reported starting from A (the min node) for stable output.
    g = _graph([_agent("A"), _agent("B"), _agent("C")], [("A", "B"), ("B", "C"), ("C", "A")])
    out = detect_delegation_cycles(g, TARGET)
    assert len(out) == 1
    assert out[0].evidence["cycle"] == ["A", "B", "C"]


def test_multiple_cycles_all_flagged_worst_first() -> None:
    g = _graph([_agent("A"), _agent("B"), _agent("C")], [("A", "B"), ("B", "A"), ("C", "C")])
    out = detect_delegation_cycles(g, TARGET)
    assert [(f.severity.value, f.evidence["length"]) for f in out] == [("HIGH", 2), ("MEDIUM", 1)]
