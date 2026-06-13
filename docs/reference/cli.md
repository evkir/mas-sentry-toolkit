# CLI Reference

All commands accept `--verbose`, `--quiet`, and `--no-color` globally.

## mas-sentry doctor

Run an environment self-check: Python version, dependency import status,
optional tooling, and scope-confirmation state.

## mas-sentry mcp scan

    mas-sentry mcp scan --target <url|stdio://path>
                        [--checks all|fingerprint|poisoning|ssrf|traversal]
                        [--out reports/mcp.json] [--confirm-scope]

Scans an MCP server. Localhost / `*.lab` / `*.test` / `*.local` targets
bypass `--confirm-scope`.

## mas-sentry abfp scan

    mas-sentry abfp scan --target mqtt://host:port [--duration 60]
                         [--threshold 500] [--out reports/abfp.json]

Passive ABFP collection, fingerprint build, scoring, and HTML report.

## mas-sentry agentic scan

    mas-sentry agentic scan --target <name> --asi all|asi01|...
                            [--tools-file tools.json] [--token JWT]
                            [--requirements requirements.txt]
                            [--out reports/agentic.json]

Static agentic scans across registered modules (ASI02/03/05/06/08/09).

## mas-sentry report convert

    mas-sentry report convert <findings.json>
                              --format html|md|json|junit|sarif
                              --out <path> [--target name]

Convert a saved findings JSON into a polished report.
