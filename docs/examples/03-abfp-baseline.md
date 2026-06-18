# Example: ABFP behavioural baseline

## Goal

Passively learn a behavioural fingerprint for the agents on an MQTT bus and
score them for anomalies.

## Setup

ABFP needs a reachable MQTT broker. Start the bundled lab broker:

```bash
docker compose -f lab/docker-compose.yml up -d mosquitto
```

## Run

```bash
mas-sentry abfp scan \
  --target mqtt://127.0.0.1:1883 \
  --duration 60 \
  --threshold 500 \
  --out reports/abfp.json
```

`--duration` is the passive collection window in seconds; `--threshold` is the
minimum messages per agent before a baseline is trusted.

## Expected output

A JSON array of behavioural findings, e.g.:

```json
[
  {
    "agent_id": "inferred_sensors_all",
    "finding_type": "NO_BASELINE",
    "severity": "MEDIUM",
    "score_contribution": 10.0,
    "description": "Agent has no known-good behavioral baseline on record",
    "evidence": { "confidence": 0.62 }
  }
]
```

## Interpretation

`NO_BASELINE` means the agent was observed but never reached the message
threshold to establish a trusted baseline - expected on a first short run.
Re-run for longer, or lower `--threshold`, to build baselines; subsequent runs
then score timing, payload, and topic-graph drift against them.

## Next step

Once baselines exist, deviations surface as timing/payload/topic findings that
map to ASI10 (Rogue Agent) and ASI09 (impersonation).
