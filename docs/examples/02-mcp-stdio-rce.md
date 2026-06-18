# Example: MCP STDIO audit

## Goal

Audit a local MCP server over STDIO for tool poisoning, SSRF, and path
traversal.

## Setup

The repo ships a deliberately vulnerable MCP server under `lab/vuln-mcp/`.
You can target it directly over STDIO - no container required.

## Run

```bash
mas-sentry mcp scan \
  --target "stdio://python lab/vuln-mcp/server.py" \
  --checks all \
  --out reports/mcp-lab.json
```

## Expected output

```
                MCP scan - stdio://python lab/vuln-mcp/server.py
| Check          | Severity | Detail                                |
|----------------|----------|---------------------------------------|
| fingerprint    | INFO     | vuln-mcp-lab 0.1.0 (3 tools)          |
| tool_poisoning | CRITICAL | exec_cmd: Suspicious patterns in tool |
| ssrf           | CRITICAL | fetch_url -> file:///etc/passwd       |
| path_traversal | HIGH     | read_file: ../../../../etc/passwd     |
| path_traversal | HIGH     | read_file: /etc/passwd                |
```

## Interpretation

`CRITICAL ssrf` means `fetch_url` followed a `file://` URL and returned local
file content - no scheme/host allowlist. `tool_poisoning` flags an `exec_cmd`
tool whose description invites command execution. Both map to ASI02 (Tool
Misuse), CWE-918 / CWE-77. Document the request/response pair for the report.

## Next step

Localhost and `.lab`/`.test`/`.local` targets bypass `--confirm-scope`. For any
remote MCP server you must pass `--confirm-scope` and have written authorisation.
Convert the findings into a customer-facing report:

```bash
mas-sentry report convert reports/mcp-lab.json \
  --format html --target lab --out reports/mcp-lab.html
```
