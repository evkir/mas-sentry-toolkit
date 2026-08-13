# CLI Reference

All commands accept `--verbose`, `--quiet`, and `--no-color` globally.

## mas-sentry doctor

Run an environment self-check: Python version, dependency import status,
optional tooling, and scope-confirmation state.

## mas-sentry mcp scan

    mas-sentry mcp scan --target <url|stdio://path>
                        [--checks all|fingerprint|poisoning|ssrf|traversal]
                        [--out reports/mcp.json] [--confirm-scope]

Scans an MCP server over the wire. Localhost / `*.lab` / `*.test` /
`*.local` targets bypass `--confirm-scope`.

## mas-sentry mcp audit-source

    mas-sentry mcp audit-source --path <dir|file>
                                [--out reports/mcp-source.json]

Audits MCP server source for the STDIO command-injection class: user-held
values reaching the command an MCP client will execute. This is the one MCP
check that reads source rather than the wire, because a live scan can only
reach a server whose command line is already built - the weakness is in how
it was built.

Takes a path, not a target, so it needs no `--confirm-scope`. A path under
which no `.py`, `.ts` or `.js` file was read reports `enumeration_gap`
rather than an empty result, since a clean tree and an unread tree produce
the same empty list.

## mas-sentry abfp scan

    mas-sentry abfp scan --target mqtt://host:port [--duration 60]
                         [--threshold 500] [--out reports/abfp.json]

Passive ABFP collection, fingerprint build, scoring, and HTML report.

## mas-sentry agentic scan

    mas-sentry agentic scan --target <name> --asi all|asi01|...
                            [--tools-file tools.json] [--token JWT]
                            [--requirements requirements.txt]
                            [--out reports/agentic.json]

Static agentic scans across registered modules (tool misuse, identity abuse,
supply chain, cascade, action audit, trust exploitation).

## mas-sentry report convert

    mas-sentry report convert <findings.json>
                              --format html|md|json|junit|sarif
                              --out <path> [--target name]

Convert a saved findings JSON into a polished report.
