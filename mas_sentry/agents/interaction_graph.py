"""
ABFP Interaction Graph — maps agent-to-agent communication paths.
Uses NetworkX to build directed graph from MQTT topic relationships.
"""
import json
from typing import Dict, List, Tuple
from mas_sentry.agents.abfp_models import AgentFingerprint

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False

from rich.console import Console
from rich.table import Table

console = Console()


class AgentInteractionGraph:
    """
    Builds a directed graph where:
      nodes = inferred agents
      edges = topic-based communication path
              (publisher → subscriber via shared topic)
    """

    def __init__(self):
        self.graph = nx.DiGraph() if HAS_NETWORKX else None
        self.edges: List[Tuple[str, str, str]] = []
        self.nodes: List[str] = []

    def build(self, fingerprints: Dict[str, AgentFingerprint]):
        """Build graph from fingerprint collection"""
        if not HAS_NETWORKX:
            console.print("[yellow][GRAPH] networkx not installed - skipping graph[/yellow]")
            return

        self.graph.clear()

        for agent_id, fp in fingerprints.items():
            self.graph.add_node(agent_id, messages=fp.message_count,
                                anomaly_score=fp.anomaly_score,
                                is_rogue=fp.is_rogue)
            if agent_id not in self.nodes:
                self.nodes.append(agent_id)

        topic_publishers: Dict[str, List[str]] = {}
        for agent_id, fp in fingerprints.items():
            for topic in fp.unique_topics:
                topic_publishers.setdefault(topic, []).append(agent_id)

        for topic, publishers in topic_publishers.items():
            for i, pub in enumerate(publishers):
                for sub in publishers:
                    if pub != sub:
                        if self.graph.has_edge(pub, sub):
                            self.graph[pub][sub]["weight"] += 1
                            self.graph[pub][sub]["topics"].append(topic)
                        else:
                            self.graph.add_edge(pub, sub,
                                                weight=1,
                                                topics=[topic])
                            self.edges.append((pub, sub, topic))

        console.print(
            f"[bold cyan][GRAPH] Built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges[/bold cyan]"
        )

    def get_central_agents(self) -> List[Tuple[str, float]]:
        """Return agents by betweenness centrality (most connected)"""
        if not HAS_NETWORKX or not self.graph:
            return []
        centrality = nx.betweenness_centrality(self.graph)
        return sorted(centrality.items(), key=lambda x: x[1], reverse=True)

    def find_isolated_agents(self) -> List[str]:
        """Agents with no connections - potential dead agents or rogues"""
        if not HAS_NETWORKX or not self.graph:
            return []
        return [n for n in self.graph.nodes if self.graph.degree(n) == 0]

    def find_hub_agents(self, min_degree: int = 3) -> List[str]:
        """Agents connected to many others - potential brokers or pivots"""
        if not HAS_NETWORKX or not self.graph:
            return []
        return [n for n in self.graph.nodes
                if self.graph.degree(n) >= min_degree]
