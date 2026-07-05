# SPDX-License-Identifier: AGPL-3.0-or-later
"""Transitive indirect-prompt-injection propagation across the agent bus.

The single-agent ``injection`` dimension flags an agent that *emits* injection
directives. It does not answer the sharper multi-agent question: did a directive
*survive a hop* from one agent to another? In a Multi-Agent System an injected
instruction spreads through legitimate inter-agent messaging like an infection -
agent B ingests A's poisoned payload and re-emits the directive, contaminating
B's own downstream consumers. Per-agent guardrails and topology-only blast-radius
both miss this: the former sees each agent in isolation, the latter counts who
*could* be reached, not whether the directive actually propagated.

This module reconstructs the propagation from observed re-emission, using two
evidence tiers ordered by confidence:

- ``verbatim``: a distinct agent later emits a payload whose hash matches an
  earlier injection-positive payload - the poisoned content was forwarded
  intact. High confidence, hash-anchored.
- ``directive``: a distinct agent later emits an injection carrying the same
  STRONG directive pattern a prior agent emitted - the instruction, not
  necessarily the bytes, crossed the boundary. Lower confidence.

Each re-emission is attributed to its *nearest* prior distinct source (the most
recent upstream emitter), yielding an infection chain rather than a dense graph.
Edges always run earlier-emit -> later-emit; an edge that would close a cycle
(re-infection ping-pong) is dropped so the result stays a DAG and depth is
well-defined.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from mas_sentry.core.injection_scan import STRONG_PATTERNS

from .scoring import Severity


@dataclass(frozen=True, slots=True)
class InjectionEvent:
    """A single injection-positive emission. Payload is never retained."""

    agent_id: str
    topic: str
    timestamp: float
    patterns: frozenset[str]
    payload_hash: str = ""


@dataclass(frozen=True, slots=True)
class PropagationEdge:
    source: str
    target: str
    tier: str  # "verbatim" | "directive"
    weight: int
    shared: tuple[str, ...]  # shared strong patterns, or the payload hash for verbatim


# verbatim evidence outranks directive when both would link the same pair.
_TIER_RANK = {"directive": 1, "verbatim": 2}


@dataclass(slots=True)
class _EdgeAcc:
    tier: str
    weight: int
    shared: set[str] = field(default_factory=set)


def build_propagation_graph(
    events: list[InjectionEvent],
    strong_patterns: frozenset[str] = STRONG_PATTERNS,
) -> nx.DiGraph:
    """Build the directed injection-propagation graph from re-emission evidence.

    Nodes are agents that emitted at least one injection. An edge ``A -> B``
    means B re-emitted a directive first seen from A (verbatim hash match, or a
    shared strong pattern). Edges are attributed to the nearest prior distinct
    source and never close a cycle, so the graph is a DAG.
    """
    graph: nx.DiGraph = nx.DiGraph()
    ordered = sorted(events, key=lambda e: e.timestamp)

    last_hash_emitter: dict[str, str] = {}
    last_pattern_emitter: dict[str, str] = {}
    acc: dict[tuple[str, str], _EdgeAcc] = {}

    for ev in ordered:
        graph.add_node(ev.agent_id, kind="agent")

        # Verbatim: identical poisoned payload previously emitted by another agent.
        src = last_hash_emitter.get(ev.payload_hash) if ev.payload_hash else None
        if src is not None and src != ev.agent_id:
            _record(acc, src, ev.agent_id, "verbatim", ev.payload_hash)
        else:
            # Directive: nearest prior distinct emitter of any shared strong pattern.
            best_src: str | None = None
            shared_here: set[str] = set()
            for pat in ev.patterns & strong_patterns:
                psrc = last_pattern_emitter.get(pat)
                if psrc is not None and psrc != ev.agent_id:
                    best_src = psrc
                    shared_here.add(pat)
            if best_src is not None and shared_here:
                _record(acc, best_src, ev.agent_id, "directive", *sorted(shared_here))

        # Update nearest-source trackers with this emission.
        if ev.payload_hash:
            last_hash_emitter[ev.payload_hash] = ev.agent_id
        for pat in ev.patterns & strong_patterns:
            last_pattern_emitter[pat] = ev.agent_id

    for (source, target), e in acc.items():
        # Drop an edge that would create a cycle; keeps the graph a DAG.
        if graph.has_node(target) and graph.has_node(source) and nx.has_path(graph, target, source):
            continue
        graph.add_edge(source, target, tier=e.tier, weight=e.weight, shared=tuple(sorted(e.shared)))
    return graph


def _record(acc: dict[tuple[str, str], _EdgeAcc], source: str, target: str, tier: str, *shared: str) -> None:
    key = (source, target)
    cur = acc.get(key)
    if cur is None:
        acc[key] = _EdgeAcc(tier=tier, weight=1, shared=set(shared))
        return
    cur.weight += 1
    cur.shared.update(shared)
    if _TIER_RANK[tier] > _TIER_RANK[cur.tier]:
        cur.tier = tier


def origin_agents(graph: nx.DiGraph) -> list[str]:
    """Emitters with no inbound propagation edge - the infection sources."""
    return sorted(n for n in graph.nodes if graph.in_degree(n) == 0)


def propagation_depth(graph: nx.DiGraph) -> dict[str, int]:
    """Longest inbound path length per node - hops a directive survived to reach it."""
    depth: dict[str, int] = {}
    for node in nx.topological_sort(graph):
        preds = list(graph.predecessors(node))
        depth[node] = 0 if not preds else 1 + max(depth[p] for p in preds)
    return depth


def propagation_chains(graph: nx.DiGraph, max_chains: int = 64) -> list[list[str]]:
    """Maximal source-to-sink infection chains, longest first, bounded."""
    origins = [n for n in graph.nodes if graph.in_degree(n) == 0]
    sinks = [n for n in graph.nodes if graph.out_degree(n) == 0]
    chains: list[list[str]] = []
    for origin in origins:
        for sink in sinks:
            if origin == sink:
                continue
            for path in nx.all_simple_paths(graph, origin, sink):
                chains.append(path)
                if len(chains) >= max_chains * 4:
                    break
    chains.sort(key=len, reverse=True)
    return chains[:max_chains]


def has_propagation(graph: nx.DiGraph) -> bool:
    """True when at least one directive crossed an agent boundary."""
    return graph.number_of_edges() > 0


# Transitive propagation is a cascading failure across agents: a hijacked goal
# does not stay local, it rides legitimate inter-agent messaging downstream.
_TRANSITIVE_TAGS: tuple[str, ...] = (
    "ASI01_Goal_Hijack",
    "ASI05_Cascading_Failure",
    "CWE-1427",
    "STRIDE_Tampering",
    "AML.T0051",
)

_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


@dataclass(frozen=True, slots=True)
class PropagationFinding:
    """A directive that reached a contaminated agent through >= 1 hop."""

    target: str
    origin: str
    depth: int
    tier: str  # worst inbound tier: "verbatim" | "directive"
    chain: list[str]
    severity: Severity
    tags: tuple[str, ...] = _TRANSITIVE_TAGS


def chain_severity(tier: str, depth: int) -> Severity:
    """Severity of a contamination hop.

    A verbatim relay (the poisoned bytes were forwarded intact) or a directive
    that survived two or more hops is CRITICAL - the blast surface multiplies
    with every hop. A directive that crossed a single boundary is HIGH.
    """
    if tier == "verbatim" or depth >= 2:
        return Severity.CRITICAL
    return Severity.HIGH


def _longest_chain_to(graph: nx.DiGraph, node: str, depth: dict[str, int]) -> list[str]:
    """Walk back to an origin, always following the deepest predecessor."""
    chain = [node]
    cur = node
    while True:
        preds = list(graph.predecessors(cur))
        if not preds:
            break
        cur = max(preds, key=lambda p: depth[p])
        chain.append(cur)
    chain.reverse()
    return chain


def propagation_findings(graph: nx.DiGraph) -> list[PropagationFinding]:
    """One finding per contaminated (non-origin) agent, worst-first.

    The tier is the worst inbound edge (verbatim outranks directive); the chain
    is the longest path from an origin down to the agent; severity follows the
    depth/tier ladder. Origins carry no finding here - they are flagged by the
    per-agent injection dimension as emitters, not as propagation targets.
    """
    depth = propagation_depth(graph)
    findings: list[PropagationFinding] = []
    for node in graph.nodes:
        preds = list(graph.predecessors(node))
        if not preds:
            continue
        tiers = {graph.edges[p, node]["tier"] for p in preds}
        tier = "verbatim" if "verbatim" in tiers else "directive"
        chain = _longest_chain_to(graph, node, depth)
        findings.append(
            PropagationFinding(
                target=node,
                origin=chain[0],
                depth=depth[node],
                tier=tier,
                chain=chain,
                severity=chain_severity(tier, depth[node]),
            )
        )
    findings.sort(key=lambda f: (_SEV_RANK[f.severity], f.depth), reverse=True)
    return findings
