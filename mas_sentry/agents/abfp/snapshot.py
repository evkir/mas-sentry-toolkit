# SPDX-License-Identifier: AGPL-3.0-or-later
"""Persistent behavioral snapshot for cross-run ABFP comparison.

A snapshot captures one scan's observed topology (the topic graph) plus a
per-agent behavioral digest (message timestamps and payload sizes). A later
scan loads a prior snapshot to compare current behavior against the learned
baseline: the graph feeds rogue-agent drift detection, the digest feeds
impersonation timing/payload analysis. Timestamps are monotonic per run;
inter-arrival intervals (used downstream) are run-relative, so the origin
offset cancels and cross-run timing comparison stays valid.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx

from .observer import MessageObserver

SNAPSHOT_VERSION = 1


@dataclass(frozen=True, slots=True)
class AgentDigest:
    """Per-agent behavioral trace: message timestamps and payload sizes."""

    timestamps: list[float] = field(default_factory=list)
    payload_sizes: list[int] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ScanSnapshot:
    """Behavioral baseline for one target: topic graph + per-agent digests."""

    target: str
    graph: nx.DiGraph
    agents: dict[str, AgentDigest]
    version: int = SNAPSHOT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "target": self.target,
            "graph": nx.node_link_data(self.graph, edges="edges"),
            "agents": {
                aid: {"timestamps": d.timestamps, "payload_sizes": d.payload_sizes} for aid, d in self.agents.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanSnapshot:
        graph: nx.DiGraph = nx.node_link_graph(data["graph"], edges="edges", directed=True)
        agents = {
            aid: AgentDigest(
                timestamps=[float(t) for t in d.get("timestamps", [])],
                payload_sizes=[int(s) for s in d.get("payload_sizes", [])],
            )
            for aid, d in data.get("agents", {}).items()
        }
        return cls(
            target=str(data["target"]), graph=graph, agents=agents, version=int(data.get("version", SNAPSHOT_VERSION))
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> ScanSnapshot:
        return cls.from_dict(json.loads(path.read_text()))


def build_snapshot(target: str, observer: MessageObserver, graph: nx.DiGraph) -> ScanSnapshot:
    """Assemble a snapshot from a completed scan's observer and topic graph."""
    agents: dict[str, AgentDigest] = {}
    for agent_id in observer.agent_ids():
        events = observer.events_for(agent_id)
        agents[agent_id] = AgentDigest(
            timestamps=[e.timestamp for e in events],
            payload_sizes=[e.payload_size for e in events],
        )
    return ScanSnapshot(target=target, graph=graph, agents=agents)
