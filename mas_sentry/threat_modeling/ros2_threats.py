# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import dataclass
from typing import List


@dataclass
class ROSThreat:
    threat_id: str
    component: str    # DDS / ROS2_TOPIC / ROS2_SERVICE / ROS2_ACTION
    title: str
    description: str
    mitigation: str
    severity: str


ROS2_DDS_THREATS: List[ROSThreat] = [
    ROSThreat(
        threat_id="ROS-S-001",
        component="DDS",
        title="DDS Domain ID Collision — Rogue Node Injection",
        description="Default DDS domain ID 0 allows any node on the network "
                    "to join and publish/subscribe without authentication.",
        mitigation="Use SROS2 with DDS security plugin. "
                   "Enforce domain isolation and node identity certificates.",
        severity="CRITICAL",
    ),
    ROSThreat(
        threat_id="ROS-T-001",
        component="ROS2_TOPIC",
        title="Unvalidated /cmd_vel Command Injection",
        description="ROS2 velocity command topic accepts messages from any node. "
                    "Attacker can send malicious velocity commands to mobile robot.",
        mitigation="Implement message authentication. "
                   "Validate command source via node identity in SROS2.",
        severity="CRITICAL",
    ),
    ROSThreat(
        threat_id="ROS-I-001",
        component="ROS2_TOPIC",
        title="Sensor Topic Eavesdropping",
        description="Camera, LIDAR, and IMU topics are readable by all nodes "
                    "in the same DDS domain without access control.",
        mitigation="Enable DDS access control plugin. "
                   "Restrict topic read permissions to authorized nodes only.",
        severity="HIGH",
    ),
    ROSThreat(
        threat_id="ROS-D-001",
        component="DDS",
        title="DDS Discovery Flood — Node Registration DoS",
        description="Attacker floods DDS discovery protocol with fake participant "
                    "announcements, degrading real-time performance.",
        mitigation="Enable DDS participant authentication. "
                   "Set discovery peer lists explicitly in DDS QoS config.",
        severity="HIGH",
    ),
]
