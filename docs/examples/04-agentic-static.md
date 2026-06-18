# Example: Agentic static scan (ASI01-ASI10)

## Goal

Run the static OWASP Agentic Top 10 checks against an agent system using only
files you already have - no live transport required.

## Run

Audit a tool inventory (ASI02) and a JWT (ASI03), plus the dependency
supply chain (ASI08):

```bash
mas-sentry agentic scan \
  --target my-agent-system \
  --tools-file tools.json \
  --token "$AGENT_JWT" \
  --requirements requirements-lock.txt \
  --asi all \
  --out reports/agentic.json
```

`tools.json` is a JSON array of `{ "name": ..., "description": ... }`. Use
`--asi asi02` (etc.) to run a single category.

## Expected output

```
                         Agentic scan - my-agent-system
| ASI                | Severity | Title                                        |
|--------------------|----------|----------------------------------------------|
| ASI02_Tool_Misuse  | HIGH     | Shell-passing tool present: exec_cmd         |
| ASI08_Supply_Chain | MEDIUM   | 12/12 requirements without exact version pin |
```

## Interpretation

Only the modules whose inputs you supply will run - pass `--tools-file` for
ASI02, `--token` for ASI03, `--requirements` for ASI08. ASI03 stays silent
on a benign token; it fires on risky ones (long-lived agent JWTs, deep
delegation chains). The live probes
(ASI01 goal hijack, ASI04 memory poisoning, ASI07 resource exhaustion) need a
transport and are driven separately.

## Next step

Feed the JSON into any report format, e.g. SARIF for code-scanning dashboards:

```bash
mas-sentry report convert reports/agentic.json \
  --format sarif --out reports/agentic.sarif
```
