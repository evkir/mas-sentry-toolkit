# Example: Environment self-check

## Goal

Verify the toolkit and its optional system dependencies before an engagement.

## Run

```bash
mas-sentry doctor
```

## Expected output

```
                               mas-sentry doctor
| Check                    | Status | Detail                            |
|--------------------------|--------|-----------------------------------|
| Python                   | OK     | 3.12.3                            |
| Import: paho.mqtt.client | OK     |                                   |
| Import: pika             | OK     |                                   |
| Import: httpx            | OK     |                                   |
| Import: networkx         | OK     |                                   |
| docker                   | WARN   | lab scenarios use docker compose  |
| mosquitto_pub            | WARN   | optional for manual MQTT testing  |
| Scope flag               | UNSET  | Required only for non-lab targets |
```

## Interpretation

`OK` rows are hard requirements and must all pass. `WARN` rows are optional:
`docker` is only needed to run the bundled lab scenarios, and `mosquitto_pub`
only for manual MQTT poking. `Scope flag UNSET` is expected on a fresh shell -
it is required only when scanning non-lab targets.

## Next step

If every import is `OK`, you are ready to run a scan. To enable active probes
against a real (authorised) target, export the scope confirmation:

```bash
export MAS_SENTRY_SCOPE_CONFIRMED=1
```
