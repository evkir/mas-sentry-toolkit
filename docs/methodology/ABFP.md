# ABFP — Agent Behavioral Fingerprinting Protocol
## Technical White Paper v0.1

### Abstract

ABFP is a passive/active behavioral analysis method for Multi-Agent Systems
deployed in IoT and Robotic ecosystems. Unlike traditional network-level
security tools, ABFP operates at the behavioral layer — building a unique
mathematical fingerprint for each agent based on five dimensions:
topic graph, timing cadence, payload signature, interaction graph,
and FSM state inference.

---

### 1. Background

Multi-Agent Systems (MAS) in IoT/Robotics present a unique attack surface.
Agents communicate over publish/subscribe protocols (MQTT, AMQP, DDS)
with minimal identity verification. A rogue agent can impersonate a
legitimate one simply by subscribing to the same topics.

---

### 2. The ABFP Model

#### 2.1 Behavioral Dimensions

| Dimension        | Metric                                      |
|------------------|---------------------------------------------|
| Topic Graph      | Publish/subscribe topic sets                |
| Timing Cadence   | Inter-message interval (mean, std, bursts)  |
| Payload Sig.     | Size distribution, encoding, entropy        |
| Interaction Graph| Agent-to-agent communication paths         |
| State Inference  | Inferred FSM state from message sequences   |
| Injection        | IPI directives in published payloads         |
| Exfil Channels   | Auto-fetch beacons emitted in payloads       |

#### 2.2 Fingerprint Vector

F(agent) = [T_graph, Timing_vector, Payload_vector, I_graph, FSM_state]

#### 2.3 Anomaly Scoring

score = weighted_sum(deviation_per_dimension) → 0..100

---

### 3. Implementation Phases

- Phase 1: Passive collection (500+ messages per agent)
- Phase 2: Fingerprint construction
- Phase 3: Active probing
- Phase 4: Anomaly scoring
- Phase 5: STRIDE-mapped threat report

---

### 4. Threat Coverage

- Rogue agent detection
- Impersonation / spoofing
- Privilege escalation via topic expansion
- Zero-day interaction path discovery
- Forensic attribution without credentials

---

### 5. References

- OWASP IoT Security Testing Guide
- STRIDE Threat Modeling (Microsoft)
- MQTT Security Fundamentals (HiveMQ)
