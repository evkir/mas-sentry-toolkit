# MAS-Sentry Toolkit -- Architecture

Unified offensive-security toolkit for multi-agent systems (MAS). The current
architecture is module-oriented: independent audit modules emit a common
`Finding` type and are composed by a single `UnifiedThreatEngine`. This replaced
the pre-pivot single-protocol `SentryEngine` design.

## Component map

```
                         +-------------------------------+
                         |   CLI (typer)                 |
                         |   abfp / mcp / agentic /      |
                         |   report / doctor             |
                         +---------------+---------------+
                                         |
                         +---------------v---------------+
                         |   UnifiedThreatEngine         |
                         |   core/threat_engine.py       |
                         |   register(name, fn) / run()  |
                         +---------------+---------------+
                                         | runs modules, dedups,
                                         | isolates failures
        +--------------------+-----------+-----------+--------------------+
        |                    |                       |                    |
        v                    v                       v                    v
  protocols/mcp/       agentic/               agents/abfp/         protocols/a2a/
  audit pack           ASI01-ASI10            behavioural          agent-card
  (RCE/SSRF/           detection              fingerprinting       audit + probes
   poisoning/          modules                (Phases 1-5)
   traversal)
        |                    |                       |                    |
        +--------------------+-----------+-----------+--------------------+
                                         |
                            each module yields core/finding.Finding
                                         |
                         +---------------v---------------+
                         |   reporting/                  |
                         |   report_model -> HTML / MD / |
                         |   JSON / SARIF / JUnit         |
                         +-------------------------------+
```

## Core (core/)

| Module            | Role                                                        |
|-------------------|-------------------------------------------------------------|
| finding.py        | `Finding` + `Severity` model, `max_severity` helper         |
| threat_engine.py  | `UnifiedThreatEngine`: registers module callables, runs them, deduplicates findings, isolates per-module failures into `EngineRun.errors` |
| adapters.py       | Convert module-native findings (agentic, mcp, abfp) into the common `Finding` |
| audit_log.py      | Append-only audit trail of scan actions                     |
| scope.py          | Scope-confirmation guard for non-lab targets                |
| types.py          | Shared type aliases + severity filters                      |

A module is any `Callable[[dict], Iterable[Finding]]`. The engine never imports
the modules directly; callers register them (see `agentic/run.py`), which keeps
the engine decoupled from any individual protocol or detector.

## Audit layers

- `protocols/mcp/` -- independent MCP client + audit pack: stdio RCE, SSRF,
  tool poisoning, prompt injection, path traversal, DNS rebinding, config
  injection, metadata tampering.
- `agentic/` -- OWASP Agentic Top 10 (2026) detectors, ASI01-ASI10. Static-input
  modules (ASI02/03/05/06/08/09) wire into the engine via `agentic/run.py`; live
  probes (ASI01/04/07) need an agent transport and run separately.
- `agents/abfp/` -- Agent Behavioural Fingerprinting Protocol: passive observation,
  baseline collection, timing/payload/topic-graph analysis, rogue + impersonation
  scoring mapped to STRIDE/ASI tags.
- `protocols/a2a/` -- A2A agent-card audit and probes.
- `protocols/` (mqtt/amqp analyzers) and `exploits/` -- transport-level MQTT/AMQP
  tooling retained from the toolkit's IoT-messaging origins.

## Threat modeling (threat_modeling/)

STRIDE mapping, CVSS v3.1 scoring, attack trees, and a `threat_aggregator` that
rolls per-threat CVSS into a single `ThreatScore` (`risk_level`,
`weighted_score`, `top_threats`).

## Reporting (reporting/)

`report_model` is the single normalized model rendered to HTML, Markdown, JSON,
SARIF, and JUnit. Module-specific renderers (`mcp_html`, `unified_html`) build on
the same model.

## Lab (lab/)

Vulnerable MCP lab plus a scenario runner used for dogfooding and end-to-end
verification of the audit pack.
