# Example: Bug-bounty / engagement prep

## Goal

Chain a scan into the deliverables an engagement needs: a triage-friendly
HTML report and a machine-readable SARIF for dashboards.

## Step 1 - scan

Pick the relevant module. For an MCP target in scope:

```bash
mas-sentry mcp scan \
  --target "stdio://python lab/vuln-mcp/server.py" \
  --checks all \
  --out reports/engagement.json
```

## Step 2 - human-readable report

```bash
mas-sentry report convert reports/engagement.json \
  --format html --target acme-mcp --out reports/engagement.html
```

## Step 3 - machine-readable SARIF

```bash
mas-sentry report convert reports/engagement.json \
  --format sarif --out reports/engagement.sarif
```

The same findings JSON also converts to `md`, `json`, and `junit`.

## Interpretation

The HTML report groups findings by severity with ASI / CWE tags for the write-up;
SARIF v2.1.0 drops straight into GitHub code scanning or any SARIF viewer for
tracking across retests.

## Scope reminder

Active probes against non-lab targets require `--confirm-scope` (or
`MAS_SENTRY_SCOPE_CONFIRMED=1`) and written authorisation. Every active action is
appended to `~/.mas-sentry/audit.jsonl` for an auditable trail.
