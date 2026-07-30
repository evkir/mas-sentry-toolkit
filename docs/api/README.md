# MAS-Sentry Toolkit -- API Reference

Hand-picked usage examples for the most common entry points. For the full,
auto-generated symbol reference see [API (generated)](../reference/api.md).

## Entry point: UnifiedThreatEngine

The engine composes independent audit modules. A module is any callable taking a
context dict and yielding `Finding` objects.

```python
from mas_sentry.core.threat_engine import UnifiedThreatEngine
from mas_sentry.core.finding import Finding, Severity

engine = UnifiedThreatEngine()


def example_module(ctx: dict) -> list[Finding]:
    return [
        Finding(
            module="example",
            title="Anonymous access",
            detail="Broker allows unauthenticated connections",
            severity=Severity.CRITICAL,
            target=ctx["target"],
            evidence={"port": 1883},
        )
    ]


engine.register("example", example_module)
run = engine.run(target="127.0.0.1", ctx={"target": "127.0.0.1"})

print(run.max_severity)  # highest severity across findings
print(run.by_severity(Severity.HIGH))  # filter
print(run.errors)  # per-module failures, isolated
```

For a real wiring of the agentic ASI modules, see `mas_sentry/agentic/run.py`.

## Core helpers

### `mas_sentry.core.types`

```python
from mas_sentry.core.types import get_critical, filter_findings

critical = get_critical(findings)
high = filter_findings(findings, "HIGH")
```

## Taxonomy tags

There is no threat-modeling package. Tags are assigned by the check that emits
the finding and travel in `Finding.tags` - see
[Threat Modeling](../methodology/threat-modeling.md) for why, and for the rules
governing when a tag is left off.

```python
from mas_sentry.core.finding import Finding, Severity

f = Finding(
    module="mqtt.anonymous_access",
    title="Broker accepts anonymous connections",
    detail="A CONNECT with no credentials was accepted.",
    severity=Severity.CRITICAL,
    target="127.0.0.1:1883",
    tags=["mqtt", "ASI03_Identity_Abuse", "CWE-306", "STRIDE_Spoofing"],
)
print(f.to_dict()["tags"])
```

Helpers for working with a finding list live in `mas_sentry.core.finding`:

```python
from mas_sentry.core.finding import max_severity, rank

print(max_severity(findings))  # highest severity present; INFO for an empty list
print(sorted(findings, key=lambda f: rank(f.severity), reverse=True))
```

## ABFP engine

### `mas_sentry.agents.fingerprinter.ABFPFingerprinter`

```python
from mas_sentry.agents.fingerprinter import ABFPFingerprinter

fp = ABFPFingerprinter(host="127.0.0.1", port=1883)
fingerprints = fp.collect(duration=60)
```
