# MCP STDIO RCE — detection methodology

## Disclosure

April 2026, OX Security: "The Mother of All AI Supply Chains" — an architectural
flaw in Anthropic's official MCP SDKs (Python/TS/Java/Rust). User-controlled
config values reach `StdioServerParameters.command`, which is then executed.
Affects 150M+ downloads across 7,000+ servers and ~200K instances.

Distinct flaws share the same architectural root:

- Unauthenticated UI injection (Flowise, LiteLLM, LangChain, LangFlow, LettaAI, LangBot)
- Hardening bypass in "protected" environments
- Zero-click prompt injection in Cursor / Windsurf / Claude Code / Gemini-CLI
- Malicious MCP marketplace distribution (9 / 11 registries successfully poisoned)

## How we detect

### Passive (static)

`audit.stdio_rce.StdioConfigAuditor` greps Python/TS/JS for sinks:

- `StdioServerParameters(command=...)` with user-tainted RHS
- `subprocess.* shell=True`
- `os.system`, f-string into `exec` (`exec(f"...{`, `exec(rf"...{`)

False-positive rate is non-zero — flag for review, not autoblock.

### Active (probe)

`audit.config_inject.probe_via_config_field` confirms a sink by *emulating a
vulnerable MCP host*: it concatenates a benign canary suffix
(`; touch /tmp/mas-sentry-canary-<uuid>`) onto the configured command and runs
the result through a shell — exactly the unsafe concatenation the disclosure
describes. Exploitability is confirmed by canary-file existence.

Design boundary: only this opt-in probe module spawns a shell. The MCP client
transport (`transport_stdio`) never does — it uses list-form `Popen` so our own
tooling cannot be injection-laundered. No destructive payload is ever issued;
the canary is a single `touch` of a unique tempfile, removed after the check.

### Tool-description injection

`audit.prompt_injection.scan_tool_definitions` matches:

- Zero-width / Unicode tag characters
- "Ignore previous instructions" family
- "New task:" directive
- System/admin role override claims
- "When called, exfiltrate / send X to Y"

These are exactly the patterns reported in the Cursor / Windsurf incidents and
the MCPTox benchmark dataset.

## Mitigation guidance (from OX recommendations)

- Block public IP access to sensitive MCP services.
- Treat external MCP config input as untrusted.
- Only install from verified registries.
- Sandbox MCP-enabled services.
