# 🛡️ MAS-Sentry-Toolkit

[![PyPI](https://img.shields.io/pypi/v/mas-sentry-toolkit?style=for-the-badge)](https://pypi.org/project/mas-sentry-toolkit/)
[![Python](https://img.shields.io/pypi/pyversions/mas-sentry-toolkit?style=for-the-badge)](https://pypi.org/project/mas-sentry-toolkit/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-orange?style=for-the-badge)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20Top%2010-red?style=for-the-badge)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
[![CI](https://github.com/evkir/mas-sentry-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/evkir/mas-sentry-toolkit/actions)
[![codecov](https://codecov.io/gh/evkir/mas-sentry-toolkit/branch/main/graph/badge.svg)](https://codecov.io/gh/evkir/mas-sentry-toolkit)
[![Downloads](https://img.shields.io/pypi/dm/mas-sentry-toolkit?style=for-the-badge)](https://pypi.org/project/mas-sentry-toolkit/)

> **Unified offensive-security toolkit for Multi-Agent Systems** — from MQTT-based IoT swarms to MCP-driven LLM agents. Aligned with OWASP Top 10 for Agentic Applications (2026) and powered by **ABFP** behavioral fingerprinting.

## Why MAS-Sentry

The MAS security landscape changed twice in 2024–2026:

1. **Anthropic's Model Context Protocol (MCP)** became the de-facto standard for LLM agent tooling — and brought a fresh class of architectural vulnerabilities (STDIO RCE affecting 200K+ servers, tool poisoning, indirect prompt injection).
2. **OWASP released the Top 10 for Agentic Applications (Dec 2025)** — formalising ASI01–ASI10 risks.

Existing tools cover **either** classical IoT messaging (MQTT/AMQP) **or** LLM-agent risks. MAS-Sentry covers **both** under one threat model.

## What's inside

| Module | Targets | Maps to |
|---|---|---|
| `protocols/mqtt` | Mosquitto, EMQX, HiveMQ, VerneMQ | IoT/Robotic MAS |
| `protocols/amqp` | RabbitMQ, ActiveMQ | Enterprise MAS |
| `protocols/mcp` | Anthropic MCP servers (STDIO / HTTP+SSE / streamable HTTP) | LLM agent tooling |
| `protocols/a2a` | Google A2A inter-agent protocol | Agent-to-agent comms |
| `agents/abfp` | Any pub/sub agent | Behavioral fingerprinting |
| `agentic/asi01-10` | LangChain / CrewAI / AutoGen / MCP hosts | OWASP Agentic Top 10 |
| `threat_modeling` | All findings | STRIDE + ASI + CWE + CVE refs |
| `reporting` | All scans | HTML / PDF / SARIF / JUnit / HackerOne preset |

## 🔬 ABFP — Agent Behavioral Fingerprinting Protocol

The core research contribution. Builds a unique fingerprint per agent across five dimensions:

| Dimension | Measured |
|---|---|
| 📡 Topic Graph | Pub/sub topology and pattern |
| ⏱️ Timing Cadence | Inter-publish interval, latency, burst signature |
| 📦 Payload Signature | Size distribution, encoding, schema entropy |
| 🔗 Interaction Graph | Agent-to-agent communication direction and frequency |
| 🧠 State Inference | FSM state inferred from message sequence |

**Phases:** passive learning → fingerprint build → active probing → anomaly scoring → STRIDE-mapped threat report.

**Enables:** rogue agent detection, impersonation attacks, privilege escalation detection, zero-day interaction-vuln discovery, forensic attribution without credentials.

## OWASP Agentic Top 10 (2026) coverage

| ID | Risk | Module |
|---|---|---|
| ASI01 | Agent Goal Hijack | `agentic/goal_hijack` |
| ASI02 | Tool Misuse & Exploitation | `agentic/tool_misuse` |
| ASI03 | Identity & Privilege Abuse | `agentic/identity_abuse` |
| ASI04 | Memory Poisoning | `agentic/memory_poisoning` |
| ASI05 | Cascading Failure | `agentic/cascade` |
| ASI06 | Untraceable Actions | `agentic/action_audit` |
| ASI07 | Resource Exhaustion | `agentic/resource_exhaustion` |
| ASI08 | Supply Chain | `agentic/supply_chain` |
| ASI09 | Human-Agent Trust Exploit | `agentic/trust_exploit` |
| ASI10 | Rogue Agent | `agentic/rogue_agent` (ties to ABFP) |

Full mapping in [THREAT_MODEL.md](THREAT_MODEL.md).

## Quick start

```bash
pipx install mas-sentry-toolkit
mas-sentry doctor
mas-sentry mqtt scan --target 192.168.1.10
mas-sentry mcp scan --target stdio://./vuln-server --checks all
mas-sentry abfp scan --target mqtt://broker.lab --duration 60
mas-sentry agentic scan --target http://langchain-app.lab --asi all
```

Run the included vulnerable lab:

```bash
docker compose -f lab/docker-compose.yml up -d
mas-sentry mqtt scan --target localhost:1883
mas-sentry mcp scan --target stdio://lab/vuln-mcp/server.py
```

## ⚖️ Legal & Scope

Active modules require explicit scope confirmation. Use only on assets you own or have written authorization to test. Designed for legal contexts: HackerOne / Bugcrowd / Intigriti / Immunefi programs and internal red-team engagements. See [SECURITY.md](SECURITY.md).

The authors and MASec Lab LLC accept no liability for any misuse of this
software or for damage arising from its use. Responsibility for operating
within applicable laws and within an authorized scope rests solely with the
user.

### Heuristic findings

ABFP behavioral fingerprinting, impersonation and rogue-agent scoring are
probabilistic signals derived from observed traffic. They may produce false
positives and false negatives and do not constitute proof that an agent is or
is not compromised. Treat scores as leads for human review, not verdicts. The
software is provided "as is", without warranty, as set out in the AGPL-3.0
license.

## License

[GNU Affero General Public License v3.0 or later](LICENSE). The author retains copyright and may grant commercial licenses separately.

## ABFP — Quick demo

```bash
# 1. Start the lab broker (Mosquitto + 3 sample agents)
docker compose -f lab/docker-compose.yml up -d

# 2. Run a 60-second ABFP passive scan (writes a behavioral baseline snapshot)
mas-sentry abfp scan --target mqtt://localhost:1883 --duration 60

# 3. Re-scan later against the baseline to flag topology drift and impersonation
mas-sentry abfp scan --target mqtt://localhost:1883 --duration 60 --baseline reports/abfp_snapshot.json

# 4. Open the generated HTML report
xdg-open reports/abfp.html
```

Output snapshot:

```
+-----------------------+-------+----------+
| Agent                 | Score | Severity |
+-----------------------+-------+----------+
| inferred_sensors      |   12  |  INFO    |
| factory_robot_r17     |   78  |  HIGH    |
+-----------------------+-------+----------+
```
