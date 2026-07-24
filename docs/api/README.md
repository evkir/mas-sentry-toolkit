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

## Threat modeling

### `mas_sentry.threat_modeling.stride_mapper.STRIDEMapper`

```python
from mas_sentry.threat_modeling.stride_mapper import STRIDEMapper

mapper = STRIDEMapper()
threats = mapper.map_from_fingerprints(fingerprints)
threats += mapper.map_from_protocol_findings(findings)
print(mapper.to_json())
```

### `mas_sentry.threat_modeling.cvss_calculator`

```python
from mas_sentry.threat_modeling.cvss_calculator import CVSSVector, calculate_cvss

vector = CVSSVector(attack_vector="N", confidentiality="H", integrity="H", availability="H")
score = calculate_cvss(vector)  # 9.8
```

### `mas_sentry.threat_modeling.threat_aggregator`

```python
from mas_sentry.threat_modeling.threat_aggregator import aggregate_threats

score = aggregate_threats(threats)
print(score.risk_level)  # CRITICAL / HIGH / MEDIUM / LOW
print(score.weighted_score)  # float
print(score.top_threats)  # top 3 by CVSS
```

## ABFP engine

### `mas_sentry.agents.fingerprinter.ABFPFingerprinter`

```python
from mas_sentry.agents.fingerprinter import ABFPFingerprinter

fp = ABFPFingerprinter(host="127.0.0.1", port=1883)
fingerprints = fp.collect(duration=60)
```
