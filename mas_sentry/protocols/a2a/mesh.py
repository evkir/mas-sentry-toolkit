# SPDX-License-Identifier: AGPL-3.0-or-later
"""A2A delegation-mesh analysis: cross-agent privilege escalation.

The single-target A2A card audit reasons over one agent in isolation; the
overbroad-scope check there names cross-agent privilege escalation as its
motive but cannot see it, because the escalation lives on the *edge* between
two cards, not inside either one. This module lifts A2A to a mesh: several
agent cards plus an operator-declared delegation topology, over which we test
the privilege-attenuation invariant.

Privilege attenuation (the 2026 A2A delegation consensus): every hop in a
delegation chain must carry equal or lesser authority than the hop before it;
no agent may delegate to a peer that holds scopes it does not itself possess.
A delegation edge A -> B where B advertises OAuth2 scopes absent from A is a
non-attenuating hop - a task handed from A reaches authority A never held,
which is cross-agent privilege escalation across the delegation boundary.

Topology is operator-declared, mirroring scope confirmation: the pentester
maps the mesh they own and are authorised to test, rather than us inferring
delegation edges from free-form card text (speculative) or observing them at
runtime (needs authentication - out of scope for a passive scanner).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import networkx as nx

from mas_sentry.core.finding import Finding, Severity, rank

from .card_audit import _collect_scope_names, _oauth2_flows
from .client import AgentCard

_ESCALATION_TAGS = ["a2a", "mesh", "ASI03_Identity_Abuse", "CWE-269", "STRIDE_Elevation_Of_Privilege"]
_CYCLE_TAGS = ["a2a", "mesh", "ASI07_Resource_Exhaustion", "CWE-674", "STRIDE_Denial_Of_Service"]


@dataclass(frozen=True, slots=True)
class MeshAgent:
    """One agent in the delegation mesh: its id, endpoint, and granted scopes."""

    id: str
    url: str
    scopes: frozenset[str]


def agent_scopes(card: AgentCard) -> frozenset[str]:
    """Union of OAuth2 scope names advertised across a card's security schemes.

    Reuses the card-audit scope extractors so the mesh sees scopes exactly as
    the single-target overbroad check does - one definition of granted scope.
    """
    schemes = card.raw.get("securitySchemes")
    if not isinstance(schemes, dict):
        return frozenset()
    names: set[str] = set()
    for scheme in schemes.values():
        names.update(_collect_scope_names(_oauth2_flows(scheme)))
    return frozenset(names)


def load_mesh_manifest(path: Path) -> tuple[list[dict[str, str]], list[tuple[str, str]]]:
    """Parse and validate a delegation-mesh manifest.

    Shape: {"agents": [{"id","url"}...], "edges": [["from_id","to_id"]...]}.
    Validates that ids are unique, urls are http(s), and every edge endpoint
    names a declared agent - a malformed topology is an operator error we
    surface loudly, not a silent empty scan.
    """
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("mesh manifest must be a JSON object")
    raw_agents = data.get("agents")
    raw_edges = data.get("edges", [])
    if not isinstance(raw_agents, list) or not raw_agents:
        raise ValueError("mesh manifest requires a non-empty agents list")
    if not isinstance(raw_edges, list):
        raise ValueError("mesh manifest edges must be a list")
    agents: list[dict[str, str]] = []
    ids: set[str] = set()
    for entry in raw_agents:
        if not isinstance(entry, dict) or "id" not in entry or "url" not in entry:
            raise ValueError("each agent needs id and url")
        aid, url = str(entry["id"]), str(entry["url"])
        if aid in ids:
            raise ValueError(f"duplicate agent id: {aid}")
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"agent {aid} url must be http(s): {url}")
        ids.add(aid)
        agents.append({"id": aid, "url": url})
    edges: list[tuple[str, str]] = []
    for edge in raw_edges:
        if not isinstance(edge, list) or len(edge) != 2:
            raise ValueError(f"each edge must be a [from, to] pair: {edge!r}")
        src, dst = str(edge[0]), str(edge[1])
        if src not in ids or dst not in ids:
            raise ValueError(f"edge {src}->{dst} references an undeclared agent")
        edges.append((src, dst))
    return agents, edges


def build_delegation_graph(agents: list[MeshAgent], edges: list[tuple[str, str]]) -> nx.DiGraph:
    """Directed delegation graph: node = agent (scopes attr), edge = delegates-to."""
    graph: nx.DiGraph = nx.DiGraph()
    for a in agents:
        graph.add_node(a.id, url=a.url, scopes=a.scopes)
    for src, dst in edges:
        graph.add_edge(src, dst)
    return graph


def _depth_to(graph: nx.DiGraph, node: str, seen: frozenset[str] = frozenset()) -> int:
    """Longest delegation depth from a root down to node; cycle-safe.

    A back-edge into an already-visited node does not extend depth, so a cyclic
    topology yields a finite depth instead of looping. Roots (no inbound
    delegation) sit at depth 0.
    """
    preds = [p for p in graph.predecessors(node) if p not in seen]
    if not preds:
        return 0
    return 1 + max(_depth_to(graph, p, seen | {node}) for p in preds)


def _chain_to(graph: nx.DiGraph, node: str) -> list[str]:
    """Deepest delegation path ending at node, following the deepest predecessor."""
    chain = [node]
    seen = {node}
    cur = node
    while True:
        preds = [p for p in graph.predecessors(cur) if p not in seen]
        if not preds:
            break
        cur = max(preds, key=lambda p: _depth_to(graph, p, frozenset(seen)))
        chain.append(cur)
        seen.add(cur)
    chain.reverse()
    return chain


def detect_scope_escalation(graph: nx.DiGraph, mesh_target: str) -> list[Finding]:
    """Flag non-attenuating delegation hops: delegate holds scopes the delegator lacks.

    One Finding per escalating edge. Severity follows the same depth ladder as
    contamination propagation: a widening hop that sits >=2 deep in a delegation
    chain is CRITICAL (the escalation compounds an already-transitive path); a
    first-hop widening is HIGH. The exact gained scopes and the delegation chain
    are carried as evidence rather than asserting exploitability.
    """
    findings: list[Finding] = []
    for src, dst in graph.edges:
        src_scopes: frozenset[str] = graph.nodes[src]["scopes"]
        dst_scopes: frozenset[str] = graph.nodes[dst]["scopes"]
        gained = dst_scopes - src_scopes
        if not gained:
            continue
        depth = _depth_to(graph, dst)
        severity = Severity.CRITICAL if depth >= 2 else Severity.HIGH
        chain = _chain_to(graph, dst)
        listed = ", ".join(sorted(gained))
        findings.append(
            Finding(
                module="a2a.mesh.priv_esc",
                title=f"Cross-agent privilege escalation: {src} delegates to {dst} with broadened scope",
                detail=(
                    f"Delegate {dst} advertises OAuth2 scope(s) [{listed}] that delegator {src} "
                    "does not hold, so a task handed down this edge reaches authority the delegator "
                    "never had. Privilege attenuation requires every delegation hop to carry equal "
                    "or lesser scope than the hop before it - narrow the delegate to a subset of the "
                    "delegator scopes"
                ),
                severity=severity,
                target=mesh_target,
                tags=list(_ESCALATION_TAGS),
                evidence={
                    "delegator": src,
                    "delegate": dst,
                    "gained_scopes": sorted(gained),
                    "delegator_scopes": sorted(src_scopes),
                    "delegate_scopes": sorted(dst_scopes),
                    "delegation_chain": chain,
                    "chain_depth": depth,
                },
            )
        )
    findings.sort(key=lambda f: (rank(f.severity), int(f.evidence["chain_depth"])), reverse=True)
    return findings


def _normalize_cycle(cycle: list[str]) -> list[str]:
    """Rotate a cycle to start at its lexicographically smallest node (stable output)."""
    if len(cycle) <= 1:
        return cycle
    i = min(range(len(cycle)), key=lambda k: cycle[k])
    return cycle[i:] + cycle[:i]


def detect_delegation_cycles(graph: nx.DiGraph, mesh_target: str) -> list[Finding]:
    """Flag cycles in the delegation graph: unbounded recursive re-delegation.

    Delegation should form a DAG - a coordinator hands work down to specialists,
    never back up. A cycle (A -> B -> ... -> A) lets a task be re-delegated around
    the loop with no base case: the recursive-DoS / delegation-deadlock vector,
    where one entering task exhausts agent workers. A self-loop (an agent
    delegating to itself) is the degenerate case, rated one step lower since
    bounded self-recursion is at least a common intentional pattern. The cycle is
    carried as evidence; the fix is breaking the back-edge or a delegation-depth cap.
    """
    findings: list[Finding] = []
    for cycle in nx.simple_cycles(graph):
        norm = _normalize_cycle(list(cycle))
        length = len(norm)
        loop = " -> ".join([*norm, norm[0]])
        severity = Severity.MEDIUM if length == 1 else Severity.HIGH
        kind = "self-delegation loop" if length == 1 else "delegation cycle"
        findings.append(
            Finding(
                module="a2a.mesh.delegation_cycle",
                title=f"Recursive re-delegation: {kind} {loop}",
                detail=(
                    f"The delegation topology contains a {kind} [{loop}]. Delegation should be "
                    "acyclic; a cycle lets a task be re-delegated around the loop without a base "
                    "case - the recursive-DoS / delegation-deadlock vector that exhausts agent "
                    "workers. Break the back-edge or enforce a delegation-depth cap"
                ),
                severity=severity,
                target=mesh_target,
                tags=list(_CYCLE_TAGS),
                evidence={"cycle": norm, "length": length},
            )
        )
    findings.sort(key=lambda f: (rank(f.severity), int(f.evidence["length"])), reverse=True)
    return findings
