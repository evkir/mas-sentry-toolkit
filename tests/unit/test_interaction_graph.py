"""
Unit tests for AgentInteractionGraph.
Run: pytest tests/unit/test_interaction_graph.py -v
"""
import pytest
from mas_sentry.agents.interaction_graph import AgentInteractionGraph, HAS_NETWORKX
from mas_sentry.agents.abfp_models import (
    AgentFingerprint, TopicProfile, TimingMetrics, PayloadMetrics
)

pytestmark = pytest.mark.skipif(
    not HAS_NETWORKX, reason="networkx not installed"
)


def make_fp(agent_id: str, topics: list) -> AgentFingerprint:
    fp = AgentFingerprint(agent_id=agent_id, first_seen=0, last_seen=60)
    fp.timing  = TimingMetrics(mean_interval_ms=1000, sample_count=10)
    fp.payload = PayloadMetrics(mean_size_bytes=48, encoding="json")
    fp.confidence = 0.9
    for t in topics:
        fp.topic_profiles[t] = TopicProfile(t, message_count=10)
    return fp


class TestAgentInteractionGraph:

    def test_build_nodes(self):
        g = AgentInteractionGraph()
        fps = {
            "sensor":     make_fp("sensor",     ["sensors/temp"]),
            "controller": make_fp("controller", ["sensors/temp", "commands/cool"]),
        }
        g.build(fps)
        assert g.graph.number_of_nodes() == 2

    def test_shared_topic_creates_edge(self):
        g = AgentInteractionGraph()
        fps = {
            "sensor":     make_fp("sensor",     ["sensors/temp"]),
            "controller": make_fp("controller", ["sensors/temp"]),
        }
        g.build(fps)
        assert g.graph.number_of_edges() > 0

    def test_no_shared_topics_no_edges(self):
        g = AgentInteractionGraph()
        fps = {
            "sensor":  make_fp("sensor",  ["sensors/temp"]),
            "logger":  make_fp("logger",  ["logs/system"]),
        }
        g.build(fps)
        assert g.graph.number_of_edges() == 0

    def test_isolated_agent_detection(self):
        g = AgentInteractionGraph()
        fps = {
            "sensor":  make_fp("sensor",  ["sensors/temp"]),
            "orphan":  make_fp("orphan",  ["unknown/topic"]),
            "controller": make_fp("controller", ["sensors/temp"]),
        }
        g.build(fps)
        isolated = g.find_isolated_agents()
        assert "orphan" in isolated

    def test_central_agents_sorted(self):
        g = AgentInteractionGraph()
        fps = {
            "hub":    make_fp("hub",    ["t1", "t2", "t3"]),
            "node_a": make_fp("node_a", ["t1"]),
            "node_b": make_fp("node_b", ["t2"]),
            "node_c": make_fp("node_c", ["t3"]),
        }
        g.build(fps)
        central = g.get_central_agents()
        assert isinstance(central, list)

    def test_json_export(self, tmp_path):
        import json, os
        g = AgentInteractionGraph()
        fps = {
            "sensor":     make_fp("sensor",     ["sensors/temp"]),
            "controller": make_fp("controller", ["sensors/temp"]),
        }
        g.build(fps)
        out = str(tmp_path / "graph.json")
        g.to_json(out)
        assert os.path.exists(out)
        with open(out) as f:
            data = json.load(f)
        assert "nodes" in data
