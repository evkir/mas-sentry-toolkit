# 🛡️ MAS-Sentry-Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.10%2B-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/OSCP--Ready-red?style=for-the-badge" />
</p>

> **A professional research framework for auditing Multi-Agent System (MAS) security.**  
> Focused on MQTT/AMQP communication interception, agent interaction vulnerabilities,  
> and threat modeling in IoT/Robotic ecosystems.

---

## 🔬 Novel Method: ABFP — Agent Behavioral Fingerprinting Protocol

> ⚡ **This is the core innovation of MAS-Sentry-Toolkit.**

**ABFP (Agent Behavioral Fingerprinting Protocol)** is a novel method developed within this project for passive and active identification, profiling, and anomaly detection of agents in Multi-Agent Systems.

### Why ABFP is different

Traditional MAS security tools focus on **network-level** attacks (MITM, replay, credential brute-force).  
ABFP operates at the **behavioral layer** — it builds a unique fingerprint for each agent by analyzing:

| Dimension | What is measured |
|-----------|-----------------|
| 📡 **Topic Graph** | Which topics does the agent publish/subscribe to, and in what pattern |
| ⏱️ **Timing Cadence** | Publish intervals, response latency, burst patterns |
| 📦 **Payload Signature** | Payload size distribution, encoding, field structure entropy |
| 🔗 **Interaction Graph** | Which agents communicate with which, direction, frequency |
| 🧠 **State Inference** | Inferred FSM state of agent from message sequence |

### What ABFP enables

- **Rogue Agent Detection** — identify agents that don't match known behavioral profiles
- **Impersonation Attacks** — detect when a legitimate agent is being spoofed
- **Privilege Escalation Detection** — agent starts publishing to topics outside its profile
- **Zero-Day Interaction Vulnerabilities** — discover undocumented agent-to-agent communication paths
- **Forensic Attribution** — match captured traffic to specific agent types even without credentials

### ABFP Phases

```
Phase 1: PASSIVE LEARNING    →  Collect 500+ messages per agent, build behavioral baseline
Phase 2: FINGERPRINT BUILD   →  Generate mathematical fingerprint (timing vector + topic graph)
Phase 3: ACTIVE PROBING      →  Inject crafted messages, observe behavioral deviation
Phase 4: ANOMALY SCORING     →  Score each agent 0-100 on behavioral deviation from baseline
Phase 5: THREAT REPORT       →  Generate structured threat report with STRIDE mapping
```

---

## 🏗️ Architecture

```
mas-sentry-toolkit/
├── mas_sentry/                    # Core Python package
│   ├── core/                      # Engine, config, session management
│   ├── protocols/                 # MQTT & AMQP analyzers
│   ├── agents/                    # ABFP fingerprinting engine
│   ├── exploits/                  # Protocol-level exploit modules
│   ├── threat_modeling/           # STRIDE + ABFP threat models
│   └── reporting/                 # Report generator (HTML/JSON/PDF)
├── lab/                           # Docker-based victim environment
│   ├── victim/                    # Mosquitto broker + Python agents
│   └── scenarios/                 # Attack scenarios for testing
├── docs/                          # Full documentation

## 📊 Roadmap

### ✅ Completed
- [x] Day 1  — Project structure
- [x] Day 2  — Core engine + session + config
- [x] Day 3  — Docker lab environment
- [x] Day 4  — Base protocol analyzer
- [x] Day 5  — MQTT analyzer
- [x] Day 6  — MQTT fingerprinting + topic walker + retained scanner
- [x] Day 7  — AMQP analyzer
- [x] Day 8  — MQTT auth attacks + will hijack
- [x] Day 9  — MQTT fuzzer
- [x] Day 10 — AMQP exchange enumeration
- [x] Day 11 — AMQP dead-letter + routing key brute-force
- [x] Day 12 — Display + JSON exporter + architecture docs
- [x] Day 13 — Retained poisoning + command injection + lab scenario
- [x] Day 14 — Protocol auto-detection + multi-target scan + base refactor

### 🔄 In Progress
- [ ] Day 15 — ABFP behavioral fingerprinting (Phase 1)
- [ ] Day 16 — ABFP timing analysis
- [ ] Day 17 — ABFP payload analysis
- [ ] Day 18 — ABFP topic graph builder
- [ ] Day 19 — ABFP anomaly detection
- [ ] Day 20 — Rogue agent detection
- [ ] Day 21 — Impersonation detection
- [ ] Day 22 — STRIDE threat modeling
- [ ] Day 25 — JSON/HTML reporting
- [ ] Day 26 — Full HTML report
- [ ] Day 30 — v1.0.0 release

## Live Demo Output

Broker Fingerprint (Mosquitto 2.0.22):
- Anonymous access ALLOWED (CRITICAL)
- guest:guest works (HIGH)
- admin:admin works (HIGH)
- Version: 2.0.22, Clients: 3, SYS topics: 51

ABFP Live Scan (30 seconds):
- Agent: inferred_sensors_all
- Messages: 31, Interval: 1000ms
- Entropy: 4.01, Confidence: 0.62
- Anomaly Score: 10/100 LOW
