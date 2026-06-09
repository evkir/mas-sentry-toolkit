# Agentic modules - OWASP Top 10 for Agentic Applications (2026)

| ID | Module | Style | What it needs |
|---|---|---|---|
| ASI01 | `agentic/goal_hijack.py` | Active probe | live agent transport + canary token |
| ASI02 | `agentic/tool_misuse.py` | Static | tool inventory JSON |
| ASI03 | `agentic/identity_abuse.py` | Static | JWT |
| ASI04 | `agentic/memory_poisoning.py` | Active probe | live agent + N rounds |
| ASI05 | `agentic/cascade.py` | Static | agent call graph |
| ASI06 | `agentic/action_audit.py` | Static | action log sample |
| ASI07 | `agentic/resource_exhaustion.py` | Active probe | telemetry hook |
| ASI08 | `agentic/supply_chain.py` | Static | requirements / package.json / MCP list |
| ASI09 | `agentic/trust_exploit.py` | Static | agent response + tool-call outcomes |
| ASI10 | `agentic/rogue_agent.py` | Static | baseline + current topic graph (from ABFP) |

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

The static scan wires ASI02/03/05/06/08/09 into the UnifiedThreatEngine.
Each module only runs when its required input is present in the context.
Use `--asi asi02` (or any single id) to run just one module; `--asi all`
(the default) runs every module that has input.

## Active probes (separate command)

Active probes (ASI01, ASI04, ASI07) require a live transport. They will be
added under `mas-sentry agentic probe` in a later release.

## Mapping back to STRIDE

| ASI | STRIDE primary |
|---|---|
| ASI01 | Tampering + Elevation of Privilege |
| ASI02 | Elevation of Privilege |
| ASI03 | Spoofing + Elevation of Privilege |
| ASI04 | Tampering |
| ASI05 | Denial of Service |
| ASI06 | Repudiation |
| ASI07 | Denial of Service |
| ASI08 | Tampering (supply path) |
| ASI09 | Spoofing (UI) |
| ASI10 | Spoofing + Elevation of Privilege |

## Output format

Findings are written as a JSON array of unified `Finding` objects
(`mas_sentry.core.finding.Finding`). Each carries `module`, `title`,
`detail`, `severity`, `target`, `tags` (ASI id + CWE), `evidence`, and a
`captured_at` ISO timestamp.
