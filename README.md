# MAS-Sentry-Toolkit

[![PyPI](https://img.shields.io/pypi/v/mas-sentry-toolkit?style=for-the-badge)](https://pypi.org/project/mas-sentry-toolkit/)
[![Python](https://img.shields.io/pypi/pyversions/mas-sentry-toolkit?style=for-the-badge)](https://pypi.org/project/mas-sentry-toolkit/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-orange?style=for-the-badge)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20Top%2010-red?style=for-the-badge)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
[![CI](https://github.com/evkir/mas-sentry-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/evkir/mas-sentry-toolkit/actions)
[![codecov](https://codecov.io/gh/evkir/mas-sentry-toolkit/branch/main/graph/badge.svg)](https://codecov.io/gh/evkir/mas-sentry-toolkit)
[![Downloads](https://img.shields.io/pypi/dm/mas-sentry-toolkit?style=for-the-badge)](https://pypi.org/project/mas-sentry-toolkit/)

> **Offensive-security scanner for multi-agent systems.** MCP and A2A agent protocols, plus MQTT agent messaging - audited against the reference SDKs rather than against our own idea of the wire. Aligned with the OWASP Top 10 for Agentic Applications (2026).

## Why this one

**The protocol clients are verified against the reference SDKs.** The lab ships an
intentionally vulnerable MCP server built on `mcp` and an A2A agent built on
`a2a-sdk`, and the integration suite drives MAS-Sentry against them. A scanner
tested only against its author's own fixtures cannot fail in the way that
matters - it just agrees with itself and returns an empty report in the field.
Pointing the reference SDKs at this one turned eleven such disagreements into
test failures, including an MCP session header we never sent (every remote
server scanned as "0 tools") and an A2A reply shape we could not read.

**A probe that could not run is reported, not dropped.** An empty finding list
means "nothing found", and it must never be produced by a scan that never
reached the target, was refused, or gave up mid-enumeration. Those cases surface
as explicit gap findings.

**Findings are named for what they prove.** A check that observes a symptom is
not promoted to the vulnerability that symptom sometimes indicates, and taxonomy
tags are left off where no clean match exists.

## What's inside

| Area | Module | Covers |
|---|---|---|
| MCP | `protocols/mcp/` | STDIO / streamable HTTP, tool poisoning, SSRF, path traversal, resource + template content, tool drift and rug-pull, DNS rebinding |
| A2A | `protocols/a2a/` | AgentCard audit, card poisoning and routing-hijack, active probes, delegation-mesh escalation and recursion |
| MQTT | `protocols/mqtt_*.py` | Broker auth posture, $SYS exposure, topic inventory, retained-payload injection and beacons |
| ABFP | `agents/abfp/` | Behavioral fingerprinting, rogue-agent scoring, injection propagation, coordination side-channel |
| Agentic | `agentic/` | OWASP ASI01-ASI10 static checks |
| Engine | `core/` | Unified `Finding`, threat engine, scope guard, injection and exfiltration primitives |
| Reporting | `reporting/` | HTML, Markdown, JSON, SARIF, JUnit |

## Install

```bash
pipx install mas-sentry-toolkit
mas-sentry doctor
```

## Commands

```bash
mas-sentry mcp scan     --target http://127.0.0.1:9800/mcp
mas-sentry mcp scan     --target 'stdio://python3 ./server.py'
mas-sentry a2a scan     --target http://127.0.0.1:9700
mas-sentry a2a mesh     --manifest mesh.json
mas-sentry mqtt scan    --target mqtt://localhost:1883 --duration 20
mas-sentry abfp scan    --target mqtt://localhost:1883 --duration 60
mas-sentry agentic scan --target my-app --requirements requirements.txt --asi all
mas-sentry report convert reports/mcp.json --format html --out reports/mcp.html
```

Active probes and non-lab targets need `--confirm-scope` (or
`MAS_SENTRY_SCOPE_CONFIRMED=1`). Anything on `localhost`, `.lab`, `.test` or
`.local` is treated as a lab target and runs without it.

The mesh manifest is `{"agents": [{"id", "url"}], "edges": [["from_id", "to_id"]]}`.

## The lab

The compose file lives in the repository root and brings up a Mosquitto broker
with three sample agents, a reference-SDK A2A agent on `:9700`, a reference-SDK
MCP server on `:9800`, and RabbitMQ.

```bash
docker compose up -d
mas-sentry mqtt scan --target mqtt://localhost:1883 --duration 10
mas-sentry mcp scan  --target http://127.0.0.1:9800/mcp
mas-sentry a2a scan  --target http://127.0.0.1:9700
```

A scan of the MCP rig, verbatim:                                                                                  Check Severity Detail
fingerprint INFO vuln-mcp-ref 0.1.0 (4 tools)
tool_poisoning CRITICAL search_notes: suspicious patterns in tool description
resource_content HIGH file://lab/policy: ignore-previous; markdown-image beacon
resource_template HIGH file://lab/notes/{name}: ignore-previous
ssrf CRITICAL fetch_url -> file:///etc/passwd
path_traversal HIGH read_file: ../../../../etc/passwd                                                                                                                                                                               ## Reading a report

Every scan writes a JSON file of unified findings; `report convert` turns that
file into HTML, Markdown, SARIF or JUnit. Each finding carries a `module`, a
`severity`, an `evidence` block and taxonomy `tags` (ASI / CWE / STRIDE, plus a
MITRE ATLAS technique where one matches cleanly).

**Severity is about what was established, not about how alarming it sounds.**

| Severity | Means |
|---|---|
| CRITICAL | Confirmed, directly exploitable: the probe got the unsafe behaviour to happen |
| HIGH | Confirmed weakness, or a payload proven to reach an agent's context |
| MEDIUM | Real signal that needs an operator judgement call, or an unassessed surface |
| LOW / INFO | Inventory, posture notes, and results recorded so the report is complete |

**Findings that describe the scan rather than the target.** These matter as much
as the vulnerabilities, because they mark the edges of what was actually tested:

- `*.enumeration_gap` - a probe did not run or a listing was refused. The surface
  behind it was **not** examined. A refusal from a target enforcing
  authentication is INFO; an unreachable target is MEDIUM.
- `inconclusive` probe results - the probe ran and the target's answer did not
  settle the question. Not a pass.
- An empty findings list is only meaningful when no gap findings sit next to it.

Start with CRITICAL and HIGH, then read the gaps to see what the scan could not
reach, then use `evidence` to reproduce before you report anything onward.

## OWASP Agentic Top 10 (2026)

| ID | Risk | Module |
|---|---|---|
| ASI01 | Agent Goal Hijack | `agentic/goal_hijack.py` |
| ASI02 | Tool Misuse & Exploitation | `agentic/tool_misuse.py` |
| ASI03 | Identity & Privilege Abuse | `agentic/identity_abuse.py` |
| ASI04 | Agentic Supply Chain | `agentic/supply_chain.py` |
| ASI05 | Unexpected Code Execution | MCP `stdio_rce` check |
| ASI06 | Memory & Context Poisoning | `agentic/memory_poisoning.py` |
| ASI07 | Insecure Inter-Agent Communication | ABFP `coordination`, A2A `mesh` |
| ASI08 | Cascading Failures | `agentic/cascade.py` |
| ASI09 | Human-Agent Trust Exploitation | `agentic/trust_exploit.py` |
| ASI10 | Rogue Agents | `agentic/rogue_agent.py` (ties to ABFP) |

Two detectors sit outside the published list, which dropped both categories
between draft and release. They are tagged `MST_Untraceable_Actions`
(`agentic/action_audit.py`) and `MST_Resource_Exhaustion`
(`agentic/resource_exhaustion.py`) rather than taking a number that now
means something else.

Full mapping in [THREAT_MODEL.md](THREAT_MODEL.md).

## ABFP - Agent Behavioral Fingerprinting

Builds a per-agent fingerprint from observed pub/sub traffic across five
dimensions - topic graph, timing cadence, payload signature, interaction graph
and inferred state - then scores later observations against a stored baseline to
flag topology drift, impersonation and rogue behaviour.

```bash
docker compose up -d
mas-sentry abfp scan --target mqtt://localhost:1883 --duration 60
mas-sentry abfp scan --target mqtt://localhost:1883 --duration 60 \
  --baseline reports/abfp_snapshot.json
mas-sentry report convert reports/abfp.json --format html --out reports/abfp.html
```

`abfp scan` writes findings to `reports/abfp.json` and a behavioral baseline to
`reports/abfp_snapshot.json`. HTML comes from `report convert`. Agents below
`--threshold` messages (default 500) are not scored, so short runs against a
quiet broker need a lower threshold.

## Legal and scope

Use only on systems you own or have written authorization to test. Active
modules require explicit scope confirmation and append to
`~/.mas-sentry/audit.jsonl`. See [SECURITY.md](SECURITY.md).

MASec Lab LLC and the authors accept no liability for misuse of this software or
for damage arising from its use. Operating within applicable law and an
authorized scope is the user's responsibility.

### Heuristic findings

ABFP fingerprinting, impersonation and rogue-agent scoring are probabilistic
signals derived from observed traffic. They produce false positives and false
negatives and do not constitute proof that an agent is or is not compromised.
Treat scores as leads for human review, not verdicts. The software is provided
"as is", without warranty, as set out in the AGPL-3.0 license.

## License

[GNU Affero General Public License v3.0 or later](LICENSE). The author retains
copyright and may grant commercial licenses separately.
