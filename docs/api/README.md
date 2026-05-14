# MAS-Sentry-Toolkit API Reference

## Core Modules

### `mas_sentry.core.engine.SentryEngine`
Main engine class orchestrating all scan operations.

```python
from mas_sentry.core.engine import SentryEngine
from mas_sentry.core.config import SentryConfig

engine = SentryEngine(config=SentryConfig())
session = engine.start_session(target="127.0.0.1", protocol="mqtt")
engine.end_session()
```

### `mas_sentry.core.session.ScanSession`
Tracks scan state and findings.

```python
session.add_finding(
    severity="CRITICAL",
    title="Anonymous Access",
    description="Broker allows unauthenticated connections",
    data={"port": 1883}
)
summary = session.summary()
```

### `mas_sentry.core.types`
Type aliases and typed helpers.

```python
from mas_sentry.core.types import get_critical, filter_findings

critical = get_critical(session.findings)
high = filter_findings(session.findings, "HIGH")
```

## Threat Modeling

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

vector = CVSSVector(attack_vector="N", confidentiality="H",
                    integrity="H", availability="H")
score = calculate_cvss(vector)  # → 9.8
```

### `mas_sentry.threat_modeling.threat_aggregator`

```python
from mas_sentry.threat_modeling.threat_aggregator import aggregate_threats

score = aggregate_threats(threats)
print(score.risk_level)      # CRITICAL / HIGH / MEDIUM / LOW
print(score.weighted_score)  # float
print(score.top_threats)     # top 3 by CVSS
```

## ABFP Engine

### `mas_sentry.agents.fingerprinter.ABFPFingerprinter`

```python
from mas_sentry.agents.fingerprinter import ABFPFingerprinter

fp = ABFPFingerprinter(host="127.0.0.1", port=1883)
fingerprints = fp.collect(duration=60)
```
