# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for ScanSnapshot persistence and assembly."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
import pytest

from mas_sentry.agents.abfp.observer import MessageEvent, MessageObserver
from mas_sentry.agents.abfp.snapshot import (
    SNAPSHOT_VERSION,
    AgentDigest,
    ScanSnapshot,
    build_snapshot,
)
from mas_sentry.agents.abfp.topic_graph import TopicGraphBuilder


def _graph() -> nx.DiGraph:
    b = TopicGraphBuilder()
    b.observe_publish("agent_a", "sensors/temp")
    b.observe_subscribe("agent_a", "cmd/a")
    b.observe_publish("agent_b", "sensors/temp")
    return b.build()


def _snapshot() -> ScanSnapshot:
    return ScanSnapshot(
        target="mqtt://127.0.0.1:1883",
        graph=_graph(),
        agents={
            "agent_a": AgentDigest(timestamps=[1.0, 1.5, 2.1], payload_sizes=[10, 12, 11]),
            "agent_b": AgentDigest(timestamps=[3.0], payload_sizes=[40]),
        },
    )


def test_roundtrip_preserves_graph_and_digests() -> None:
    snap = _snapshot()
    restored = ScanSnapshot.from_dict(snap.to_dict())
    assert restored.version == SNAPSHOT_VERSION
    assert restored.target == snap.target
    assert set(restored.graph.nodes) == set(snap.graph.nodes)
    assert set(restored.graph.edges) == set(snap.graph.edges)
    assert nx.get_edge_attributes(restored.graph, "kind") == nx.get_edge_attributes(snap.graph, "kind")
    assert restored.agents["agent_a"].timestamps == [1.0, 1.5, 2.1]
    assert restored.agents["agent_a"].payload_sizes == [10, 12, 11]


def test_save_load_file(tmp_path: Path) -> None:
    snap = _snapshot()
    path = tmp_path / "snap.json"
    snap.save(path)
    assert path.exists()
    restored = ScanSnapshot.load(path)
    assert restored.target == snap.target
    assert set(restored.graph.edges) == set(snap.graph.edges)
    assert restored.agents["agent_b"].payload_sizes == [40]


def test_build_snapshot_from_observer() -> None:
    obs = MessageObserver()
    for i in range(3):
        obs.record(MessageEvent.now("agent_a", "sensors/temp", b"x" * (10 + i)))
    obs.record(MessageEvent.now("agent_b", "sensors/temp", b"y" * 40))
    snap = build_snapshot("mqtt://x:1883", obs, _graph())
    assert set(snap.agents) == {"agent_a", "agent_b"}
    assert len(snap.agents["agent_a"].timestamps) == 3
    assert snap.agents["agent_a"].payload_sizes == [10, 11, 12]
    assert snap.agents["agent_b"].payload_sizes == [40]


def test_from_dict_defaults_version() -> None:
    snap = ScanSnapshot.from_dict(
        {"target": "t", "graph": nx.node_link_data(nx.DiGraph(), edges="edges"), "agents": {}}
    )
    assert snap.version == SNAPSHOT_VERSION
    assert snap.agents == {}


def test_from_dict_rejects_newer_version() -> None:
    data = {
        "version": SNAPSHOT_VERSION + 1,
        "target": "t",
        "graph": nx.node_link_data(nx.DiGraph(), edges="edges"),
        "agents": {},
    }
    with pytest.raises(ValueError, match="newer than supported"):
        ScanSnapshot.from_dict(data)
