# Threat Modeling Guide — MAS-Sentry-Toolkit

## Overview

MAS-Sentry uses STRIDE to systematically identify threats in
Multi-Agent System deployments over MQTT and AMQP.

## STRIDE Categories in MAS Context

| Category | MAS Example | Severity |
|----------|-------------|----------|
| **Spoofing** | Client ID impersonation | CRITICAL |
| **Tampering** | Retained message poisoning | HIGH |
| **Repudiation** | No message signing | MEDIUM |
| **Info Disclosure** | Wildcard topic enumeration | HIGH |
| **Denial of Service** | Message flood | HIGH |
| **Elevation of Privilege** | Topic ACL bypass | CRITICAL |

## Usage

```python
from mas_sentry.threat_modeling.stride import MAS_MQTT_THREATS
from mas_sentry.threat_modeling.stride_reporter import format_threat_report

report = format_threat_report(MAS_MQTT_THREATS)
print(report)
```

## ABFP → STRIDE Automatic Mapping

```python
from mas_sentry.threat_modeling.abfp_stride_mapper import map_session_findings

# session.findings populated by ABFP engine
threats = map_session_findings(session.findings)
```

## Threat Catalog

Current catalog covers 6 STRIDE categories with MAS-specific
attack scenarios validated against real MQTT broker deployments.
