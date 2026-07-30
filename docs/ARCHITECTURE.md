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
                         |   Finding -> HTML / MD /      |
                         |   JSON / SARIF / JUnit        |
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

## Threat modeling (core/threat_engine.py)

`UnifiedThreatEngine` composes audit modules, deduplicates findings across them
and isolates per-module failures into `run.errors`, so one failing module cannot
abort a scan. It reports `max_severity`; it does not compute a weighted risk
score, and CVSS is not implemented.

ASI/CWE/STRIDE/ATLAS tags are assigned by the check that emits each finding
rather than by a separate mapper, because only the detection site knows enough
to classify what it found. See `docs/methodology/threat-modeling.md`.

## Reporting (reporting/)

`core.finding.Finding` is the single normalized model every renderer consumes:
`unified_html`, `markdown`, `structured` (JSON and JUnit) and `sarif`.
`report convert` reads a scan JSON, routes each row to the adapter that
understands its shape, and renders. A finding that does not reach this path is
invisible in every output format, so new scan surfaces emit `Finding` directly.

## Lab (lab/)

Intentionally vulnerable rigs built on the reference SDKs - `lab/mcp/server.py`
on `mcp`, `lab/a2a/agent.py` on `a2a-sdk` - plus a Mosquitto broker with sample
agents and a scenario runner. Building the victims on the reference
implementations is deliberate: a hand-written victim only reflects the scanner
own assumptions about the wire, so it cannot expose a divergence between what
MAS-Sentry emits and what a real server accepts.
