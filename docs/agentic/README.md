# Agentic modules - OWASP Top 10 for Agentic Applications (2026)

Numbering follows the list published on 9 December 2025. MST previously
carried a pre-release ordering; if you have reports from before that fix,
their ASI numbers do not mean what the current ones mean.

| ID | Selector | Module | Style | What it needs |
|---|---|---|---|---|
| ASI01 Agent Goal Hijack | `goal_hijack` | `agentic/goal_hijack.py` | Active probe | live agent transport + canary token |
| ASI02 Tool Misuse | `tool_misuse` | `agentic/tool_misuse.py` | Static | tool inventory JSON |
| ASI03 Identity & Privilege Abuse | `identity_abuse` | `agentic/identity_abuse.py` | Static | JWT |
| ASI04 Agentic Supply Chain | `supply_chain` | `agentic/supply_chain.py` | Static | requirements / package.json / MCP list |
| ASI05 Unexpected Code Execution | - | (no agentic module; see MCP `stdio_rce`) | - | - |
| ASI06 Memory & Context Poisoning | `memory_poisoning` | `agentic/memory_poisoning.py` | Active probe | live agent + N rounds |
| ASI07 Insecure Inter-Agent Communication | - | (see ABFP `coordination`, A2A `mesh`) | - | - |
| ASI08 Cascading Failures | `cascade` | `agentic/cascade.py` | Static | agent call graph |
| ASI09 Human-Agent Trust Exploitation | `trust_exploit` | `agentic/trust_exploit.py` | Static | agent response + tool-call outcomes |
| ASI10 Rogue Agents | `rogue_agent` | `agentic/rogue_agent.py` | Static | baseline + current topic graph (from ABFP) |

Two detectors have no home in the published list, having been dropped
between the draft and the release. They keep an `MST_` prefix rather than a
number that now means something else:

| Tag | Selector | Module | Style | What it needs |
|---|---|---|---|---|
| `MST_Untraceable_Actions` | `action_audit` | `agentic/action_audit.py` | Static | action log sample |
| `MST_Resource_Exhaustion` | `resource_exhaustion` | `agentic/resource_exhaustion.py` | Active probe | telemetry hook |

## Usage

```bash
mas-sentry agentic scan \
  --target prod-router \
  --asi all \
  --tools-file ./inventory/tools.json \
  --token "$AGENT_JWT" \
  --requirements ./requirements.txt \
  --out reports/agentic.json
```

The static scan wires tool misuse, identity abuse, supply chain, cascade,
action audit and trust exploitation into the UnifiedThreatEngine. Each
module only runs when its required input is present in the context.

`--asi` takes a category number (`asi04`), a full tag
(`ASI04_Supply_Chain`) or the selector name (`supply_chain`); `--asi all`
(the default) runs every module that has input. The selector names carry no
number on purpose - a name that encodes one goes stale the moment the list
is renumbered.

## Active probes (separate command)

Goal hijack, memory poisoning and resource exhaustion require a live
transport. They will be added under `mas-sentry agentic probe` in a later
release.

## Mapping back to STRIDE

| ASI | STRIDE primary |
|---|---|
| ASI01 Agent Goal Hijack | Tampering + Elevation of Privilege |
| ASI02 Tool Misuse | Elevation of Privilege |
| ASI03 Identity & Privilege Abuse | Spoofing + Elevation of Privilege |
| ASI04 Agentic Supply Chain | Tampering (supply path) |
| ASI05 Unexpected Code Execution | Elevation of Privilege |
| ASI06 Memory & Context Poisoning | Tampering |
| ASI07 Insecure Inter-Agent Communication | Spoofing + Information Disclosure |
| ASI08 Cascading Failures | Denial of Service |
| ASI09 Human-Agent Trust Exploitation | Spoofing (UI) |
| ASI10 Rogue Agents | Spoofing + Elevation of Privilege |
| `MST_Untraceable_Actions` | Repudiation |
| `MST_Resource_Exhaustion` | Denial of Service |

## Output format

Findings are written as a JSON array of unified `Finding` objects
(`mas_sentry.core.finding.Finding`). Each carries `module`, `title`,
`detail`, `severity`, `target`, `tags` (ASI id + CWE), `evidence`, and a
`captured_at` ISO timestamp.
