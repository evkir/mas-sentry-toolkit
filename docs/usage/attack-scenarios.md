# Attack Scenario Examples

## Scenario 1: Unauthenticated MQTT Broker

```bash
# Step 1: Scan for anonymous access
mas-sentry scan --target 192.168.1.100 --protocol mqtt

# Step 2: Run ABFP to fingerprint agents
mas-sentry abfp --target 192.168.1.100 --duration 60

# Step 3: Generate STRIDE threat report
mas-sentry report --session <session-id> --format html
```

**Expected findings:**
- CRITICAL: Anonymous access allowed
- HIGH: Wildcard topic enumeration possible
- HIGH: No TLS encryption

---

## Scenario 2: Agent Behavioral Drift Detection

```bash
# Collect baseline (legitimate traffic)
mas-sentry abfp --target 192.168.1.100 --duration 120 --save-baseline

# Monitor for drift (run after suspected compromise)
mas-sentry abfp --target 192.168.1.100 --duration 60 --compare-baseline
```

**ABFP flags triggered:**
- `TOPIC_ESCALATION` → MAS-E-001 (CRITICAL)
- `BURST_DETECTED`   → MAS-D-001 (HIGH)
- `CLONE_DETECTED`   → MAS-S-002 (HIGH)

---

## Scenario 3: Docker Lab (local testing)

```bash
# Start lab
docker-compose up -d

# Full scan against lab
mas-sentry scan --target localhost --protocol mqtt
mas-sentry abfp --target localhost --duration 30
mas-sentry report --session <session-id> --format html

# Open report
xdg-open reports/<session-id>.html
```

---

## Scenario 4: CVSS Scoring Custom Vulnerability

```python
from mas_sentry.threat_modeling.cvss_calculator import CVSSVector, calculate_cvss

# MQTT broker — network access, no auth, full impact
v = CVSSVector(
    attack_vector="N",
    attack_complexity="L",
    privileges_required="N",
    user_interaction="N",
    scope="C",
    confidentiality="H",
    integrity="H",
    availability="H",
)
print(calculate_cvss(v))  # → 10.0
```
