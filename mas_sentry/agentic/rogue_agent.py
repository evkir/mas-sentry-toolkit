# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASI10 — Rogue Agent.

Thin adapter that re-emits ABFP rogue findings (mas_sentry.agents.abfp.rogue)
as agentic findings, so the agentic pipeline can surface them alongside
ASI01-ASI09 results without consumers needing to know about the ABFP layer.
"""

from __future__ import annotations

import networkx as nx

from mas_sentry.agents.abfp.rogue import RogueFinding, detect_rogue

from .base import AgenticFinding, AsiCategory


def audit_for_rogue_agents(
    baseline_graph: nx.DiGraph,
    current_graph: nx.DiGraph,
    target: str,
) -> list[AgenticFinding]:
    rogue_findings: list[RogueFinding] = detect_rogue(baseline_graph, current_graph)
    out: list[AgenticFinding] = []
    for rf in rogue_findings:
        if not rf.is_rogue:
            continue
        out.append(
            AgenticFinding(
                asi=AsiCategory.ROGUE_AGENT,
                severity=rf.score.severity.value,
                title=(f"Rogue agent '{rf.agent_id}' (ABFP score {rf.score.total}/100)"),
                detail=("Agent identity or behaviour outside learned fingerprint baseline"),
                target=target,
                evidence={
                    "agent_id": rf.agent_id,
                    "score": rf.score.total,
                    "new_topics": rf.diff_summary.get("new_topics", []),
                    "removed_topics": rf.diff_summary.get("removed_topics", []),
                },
                cwe="CWE-940",
            )
        )
    return out
