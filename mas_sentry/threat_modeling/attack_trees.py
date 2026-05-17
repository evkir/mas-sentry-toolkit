# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import dataclass, field


@dataclass
class AttackNode:
    node_id: str
    description: str
    likelihood: str  # HIGH / MEDIUM / LOW
    required_access: str  # NONE / NETWORK / LOCAL / PHYSICAL
    children: list["AttackNode"] = field(default_factory=list)


@dataclass
class AttackTree:
    tree_id: str
    goal: str
    root: AttackNode
    protocol: str = "MQTT"


IoT_ATTACK_TREES = [
    AttackTree(
        tree_id="AT-001",
        goal="Compromise MAS coordinator agent",
        protocol="MQTT",
        root=AttackNode(
            node_id="AT-001-ROOT",
            description="Take control of coordinator",
            likelihood="HIGH",
            required_access="NONE",
            children=[
                AttackNode(
                    node_id="AT-001-A",
                    description="Impersonate coordinator via client_id spoofing",
                    likelihood="HIGH",
                    required_access="NETWORK",
                    children=[
                        AttackNode(
                            node_id="AT-001-A1",
                            description="Broker allows anonymous connections",
                            likelihood="HIGH",
                            required_access="NONE",
                        ),
                        AttackNode(
                            node_id="AT-001-A2",
                            description="No mutual TLS enforced",
                            likelihood="MEDIUM",
                            required_access="NONE",
                        ),
                    ],
                ),
                AttackNode(
                    node_id="AT-001-B",
                    description="Poison retained command topic",
                    likelihood="MEDIUM",
                    required_access="NETWORK",
                    children=[
                        AttackNode(
                            node_id="AT-001-B1",
                            description="No ACL on command topics",
                            likelihood="HIGH",
                            required_access="NONE",
                        ),
                    ],
                ),
            ],
        ),
    ),
    AttackTree(
        tree_id="AT-002",
        goal="Exfiltrate sensor data from MAS",
        protocol="MQTT",
        root=AttackNode(
            node_id="AT-002-ROOT",
            description="Passive data exfiltration",
            likelihood="HIGH",
            required_access="NONE",
            children=[
                AttackNode(
                    node_id="AT-002-A",
                    description="Subscribe to all topics via wildcard #",
                    likelihood="HIGH",
                    required_access="NETWORK",
                ),
                AttackNode(
                    node_id="AT-002-B",
                    description="Read unencrypted $SYS broker statistics",
                    likelihood="HIGH",
                    required_access="NONE",
                ),
            ],
        ),
    ),
]
