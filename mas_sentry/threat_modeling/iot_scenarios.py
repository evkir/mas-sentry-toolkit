"""
IoT/Robotic ecosystem attack scenarios for MAS-Sentry.
Pre-built attack trees for common MAS deployments.
"""
from dataclasses import dataclass, field
from typing import List
from rich.console import Console
from rich.tree import Tree

console = Console()


@dataclass
class AttackStep:
    step_id: str
    title: str
    technique: str
    tool_module: str
    expected_finding: str


@dataclass
class AttackScenario:
    scenario_id: str
    title: str
    target_environment: str
    threat_actor: str
    steps: List[AttackStep] = field(default_factory=list)
    mitre_ref: str = ""

    def print_tree(self):
        tree = Tree(
            f"[bold red]Scenario {self.scenario_id}:[/bold red] "
            f"[bold]{self.title}[/bold]"
        )
        tree.add(f"[dim]Target:[/dim] {self.target_environment}")
        tree.add(f"[dim]Actor:[/dim]  {self.threat_actor}")
        if self.mitre_ref:
            tree.add(f"[dim]MITRE:[/dim]  {self.mitre_ref}")
        steps_node = tree.add("[bold cyan]Attack Steps:[/bold cyan]")
        for step in self.steps:
            s = steps_node.add(
                f"[yellow]{step.step_id}[/yellow] {step.title}"
            )
            s.add(f"[dim]Technique:[/dim] {step.technique}")
            s.add(f"[dim]Module:[/dim]    {step.tool_module}")
            s.add(f"[dim]Finds:[/dim]     {step.expected_finding}")
        console.print(tree)


IOT_SCENARIOS: List[AttackScenario] = [

    AttackScenario(
        scenario_id="SC-001",
        title="Smart Factory Sensor Takeover",
        target_environment="Industrial IoT — MQTT broker + sensor agents",
        threat_actor="Insider / nation-state",
        mitre_ref="T0830 (Manipulation of Control)",
        steps=[
            AttackStep("1", "Broker Recon",
                       "Anonymous MQTT connect, $SYS enumeration",
                       "mqtt_fingerprint.MQTTBrokerFingerprinter",
                       "Broker version, client count, anonymous access"),
            AttackStep("2", "Topic Enumeration",
                       "Wildcard subscription (#)",
                       "mqtt_topic_walker.MQTTTopicWalker",
                       "Full topic tree, sensor data, command channels"),
            AttackStep("3", "ABFP Baseline",
                       "Passive fingerprinting (Phase 1+2)",
                       "fingerprinter.ABFPFingerprinter",
                       "Agent behavioral profiles"),
            AttackStep("4", "Command Injection",
                       "Publish to commands/actuator/cooling",
                       "mqtt_retained.MQTTRetainedScanner.poison()",
                       "Unauthorized actuator activation"),
            AttackStep("5", "Persistence",
                       "Will message on status topic",
                       "mqtt_will_hijack.MQTTWillHijacker",
                       "Persistent false state on broker"),
        ]
    ),

    AttackScenario(
        scenario_id="SC-002",
        title="Robotic Swarm Agent Impersonation",
        target_environment="ROS2-like multi-robot MQTT coordination",
        threat_actor="External attacker / rogue node",
        mitre_ref="T0866 (Exploitation of Remote Services)",
        steps=[
            AttackStep("1", "Network Scan",
                       "Identify MQTT broker on network",
                       "mqtt_auth_check.MQTTAuthChecker",
                       "Open port 1883, anonymous access"),
            AttackStep("2", "Agent Discovery",
                       "ABFP passive collection",
                       "fingerprinter.ABFPFingerprinter",
                       "Robot agent IDs and behavioral profiles"),
            AttackStep("3", "Clone Fingerprint",
                       "Match target agent timing and topics",
                       "Custom — mirror fingerprint",
                       "Undetected presence on network"),
            AttackStep("4", "Inject Commands",
                       "Publish fake sensor readings",
                       "mqtt_retained.MQTTRetainedScanner.poison()",
                       "Robots respond to false data"),
            AttackStep("5", "ABFP Detection",
                       "Run anomaly detection vs baseline",
                       "anomaly_detector.AnomalyDetector",
                       "HIGH_ENTROPY flag on impersonator"),
        ]
    ),
]


def print_all_scenarios():
    for scenario in IOT_SCENARIOS:
        scenario.print_tree()
        console.print()
