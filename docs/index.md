# MAS-Sentry Toolkit

The unified offensive-security toolkit for Multi-Agent Systems - from
MQTT-based IoT swarms to MCP-driven LLM agents. Aligned with **OWASP Agentic
Top 10 (2026)** and powered by **ABFP** behavioural fingerprinting.

## What's inside

- **MQTT / AMQP** - classical messaging-MAS pentest modules.
- **MCP** - independent JSON-RPC implementation for offensive testing.
  Detects STDIO RCE, SSRF, tool poisoning, path traversal.
- **A2A** - Google Agent-to-Agent protocol client plus active probes.
- **ABFP** - Agent Behavioural Fingerprinting (Phases 1-5).
- **Agentic** - ASI01-ASI10 detection modules.

## Quick start

```bash
pipx install mas-sentry-toolkit
mas-sentry doctor
mas-sentry mcp scan --target stdio://./lab/vuln-mcp/server.py --checks all
```

See the [methodology pages](methodology/ABFP.md) for technical depth.

## Project resources

- [Threat model](https://github.com/evkir/mas-sentry-toolkit/blob/main/THREAT_MODEL.md)
- [Lab environment](https://github.com/evkir/mas-sentry-toolkit/blob/main/lab/README.md)
- [Source](https://github.com/evkir/mas-sentry-toolkit)
