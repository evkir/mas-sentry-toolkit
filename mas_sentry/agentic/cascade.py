# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASI08 — Cascading Failure detection.

Given a multi-agent call graph, detect:
- Cycles (agent A → B → A) without circuit-breakers
- Single points of failure (one agent with high in-degree)
- Absent retry-budget configuration
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .base import AgenticFinding, AsiCategory

# Threshold for fan-in-based "single point of failure" flag.
HIGH_IN_DEGREE_THRESHOLD = 4
# Minimum number of edges lacking retry-budget config before we surface it.
RETRY_BUDGET_MIN_EDGES = 3


@dataclass(slots=True)
class AgentEdge:
    src: str
    dst: str
    has_breaker: bool = False
    has_retry_budget: bool = False


def audit_call_graph(edges: list[AgentEdge], target: str) -> list[AgenticFinding]:
    g: nx.DiGraph = nx.DiGraph()
    for e in edges:
        g.add_edge(e.src, e.dst, breaker=e.has_breaker, retry=e.has_retry_budget)

    findings: list[AgenticFinding] = []

    # 1. Cycles without breakers — runaway failure amplification
    for cycle in nx.simple_cycles(g):
        if len(cycle) < 2:
            # Self-loop (a → a). Worth flagging but not a "cycle" in the
            # cascading sense; skip for the MVP.
            continue
        breakers = [g[cycle[i]][cycle[(i + 1) % len(cycle)]].get("breaker", False) for i in range(len(cycle))]
        if not any(breakers):
            findings.append(
                AgenticFinding(
                    asi=AsiCategory.CASCADING_FAILURE,
                    severity="HIGH",
                    title=f"Agent call cycle without circuit breaker: {' → '.join(cycle)}",
                    detail=("Cycle can amplify failures and exhaust budget without recovery"),
                    target=target,
                    evidence={"cycle": cycle},
                    cwe="CWE-835",
                )
            )

    # 2. High in-degree agents — single point of failure
    for node in g.nodes:
        indeg = g.in_degree(node)
        if indeg >= HIGH_IN_DEGREE_THRESHOLD:
            findings.append(
                AgenticFinding(
                    asi=AsiCategory.CASCADING_FAILURE,
                    severity="MEDIUM",
                    title=f"Single point of failure: '{node}' (in-degree {indeg})",
                    detail=("High fan-in concentrates risk; one failure cascades to many callers"),
                    target=target,
                    evidence={"agent": node, "in_degree": indeg},
                )
            )

    # 3. Edges lacking retry budget — runaway-retry surface
    no_budget = [[u, v] for u, v, d in g.edges(data=True) if not d.get("retry")]
    if len(no_budget) >= RETRY_BUDGET_MIN_EDGES:
        findings.append(
            AgenticFinding(
                asi=AsiCategory.CASCADING_FAILURE,
                severity="LOW",
                title=f"{len(no_budget)} agent edges lack retry-budget config",
                detail=("Without retry budgets, transient errors can trigger runaway loops"),
                target=target,
                evidence={"edges": no_budget[:10]},
            )
        )

    return findings
