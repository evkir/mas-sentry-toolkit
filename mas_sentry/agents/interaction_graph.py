# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ABFP Interaction Graph — maps agent-to-agent communication paths.
Uses NetworkX to build directed graph from MQTT topic relationships.
"""

import json

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
        self.graph: nx.DiGraph | None = nx.DiGraph() if HAS_NETWORKX else None
        self.edges: list[tuple[str, str, str]] = []
        self.nodes: list[str] = []

    def build(self, fingerprints: dict[str, AgentFingerprint]):
        """Build graph from fingerprint collection"""
        if not HAS_NETWORKX:
            console.print("[yellow][GRAPH] networkx not installed - skipping graph[/yellow]")
            return

        assert self.graph is not None  # guaranteed by HAS_NETWORKX check above
        self.graph.clear()

        for agent_id, fp in fingerprints.items():
            self.graph.add_node(
                agent_id,
                messages=fp.message_count,
                anomaly_score=fp.anomaly_score,
                is_rogue=fp.is_rogue,
            )
            if agent_id not in self.nodes:
                self.nodes.append(agent_id)

        topic_publishers: dict[str, list[str]] = {}
        for agent_id, fp in fingerprints.items():
            for topic in fp.unique_topics:
                topic_publishers.setdefault(topic, []).append(agent_id)

        for topic, publishers in topic_publishers.items():
            for _i, pub in enumerate(publishers):
                for sub in publishers:
                    if pub != sub:
                        if self.graph.has_edge(pub, sub):
                            self.graph[pub][sub]["weight"] += 1
                            self.graph[pub][sub]["topics"].append(topic)
                        else:
                            self.graph.add_edge(pub, sub, weight=1, topics=[topic])
                            self.edges.append((pub, sub, topic))

        console.print(
            f"[bold cyan][GRAPH] Built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges[/bold cyan]"
        )

    def get_central_agents(self) -> list[tuple[str, float]]:
        """Return agents by betweenness centrality (most connected)"""
        if not HAS_NETWORKX or not self.graph:
            return []
        centrality = nx.betweenness_centrality(self.graph)
        return sorted(centrality.items(), key=lambda x: x[1], reverse=True)

    def find_isolated_agents(self) -> list[str]:
        """Agents with no connections - potential dead agents or rogues"""
        if not HAS_NETWORKX or not self.graph:
            return []
        return [n for n in self.graph.nodes if self.graph.degree(n) == 0]

    def find_hub_agents(self, min_degree: int = 3) -> list[str]:
        """Agents connected to many others - potential brokers or pivots"""
        if not HAS_NETWORKX or not self.graph:
            return []
        return [n for n in self.graph.nodes if self.graph.degree(n) >= min_degree]

    def print_summary(self):
        """Print graph summary table"""
        if not HAS_NETWORKX or not self.graph:
            return

        table = Table(title="[bold]Agent Interaction Graph[/bold]")
        table.add_column("Agent", style="cyan")
        table.add_column("In", justify="right", style="green")
        table.add_column("Out", justify="right", style="yellow")
        table.add_column("Total", justify="right")
        table.add_column("Centrality", justify="right", style="magenta")
        table.add_column("Role", style="bold")

        centrality = nx.betweenness_centrality(self.graph)

        for node in sorted(self.graph.nodes):
            in_deg = self.graph.in_degree(node)
            out_deg = self.graph.out_degree(node)
            total = in_deg + out_deg
            cent = centrality.get(node, 0.0)

            if total == 0:
                role = "[dim]isolated[/dim]"
            elif out_deg > in_deg * 2:
                role = "[yellow]publisher[/yellow]"
            elif in_deg > out_deg * 2:
                role = "[blue]subscriber[/blue]"
            elif cent > 0.3:
                role = "[red]hub[/red]"
            else:
                role = "[green]peer[/green]"

            is_rogue = self.graph.nodes[node].get("is_rogue", False)
            if is_rogue:
                role = "[bold red]ROGUE[/bold red]"

            table.add_row(node, str(in_deg), str(out_deg), str(total), f"{cent:.2f}", role)
        console.print(table)

        isolated = self.find_isolated_agents()
        if isolated:
            console.print(f"[yellow][GRAPH] Isolated agents: {isolated}[/yellow]")

        hubs = self.find_hub_agents()
        if hubs:
            console.print(f"[red][GRAPH] Hub agents (high connectivity): {hubs}[/red]")

    def to_dot(self, path: str = "reports/agent_graph.dot"):
        """Export graph as DOT file for Graphviz visualization"""
        if not HAS_NETWORKX or not self.graph:
            return
        import os

        os.makedirs("reports", exist_ok=True)
        nx.drawing.nx_pydot.write_dot(self.graph, path)
        console.print(f"[green][GRAPH] DOT file saved: {path}[/green]")
        console.print(f"[dim]  Visualize: dot -Tpng {path} -o reports/graph.png[/dim]")

    def to_json(self, path: str = "reports/agent_graph.json"):
        """Export graph as JSON node-link format"""
        if not HAS_NETWORKX or not self.graph:
            return
        import os

        os.makedirs("reports", exist_ok=True)
        data = nx.node_link_data(self.graph)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green][GRAPH] JSON saved: {path}[/green]")
