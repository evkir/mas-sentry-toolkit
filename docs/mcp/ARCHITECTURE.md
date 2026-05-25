# MCP module architecture

## Why an independent impl

The official Anthropic `mcp` Python SDK is a **client for well-behaved applications**. It:

- validates JSON schemas before sending,
- coerces types,
- refuses to encode malformed JSON-RPC,
- normalises capabilities into typed dataclasses.

Every one of those is the opposite of what a pentest tool needs. We must be able to:

- send a `tools/list` request with an extra field that the spec forbids — to test what the server does with it,
- send a `id: -32700` that should round-trip raw,
- send 100 simultaneous `initialize` calls,
- truncate the response mid-stream and reconnect,
- omit `jsonrpc: "2.0"` to see if the server still answers.

None of that is possible through the SDK without monkey-patching, which is brittle and would couple our findings to SDK internals.

## Layering
┌─────────────────────────────────────────┐
│ audit/* — RCE, SSRF, poisoning, etc.    │
├─────────────────────────────────────────┤
│ client.py — high-level RPC convenience  │
├─────────────────────────────────────────┤
│ transport_stdio / transport_http        │
├─────────────────────────────────────────┤
│ jsonrpc.py — codec (intentionally lax)  │
└─────────────────────────────────────────┘
## Boundary rule

Schemas referenced from the upstream spec live in `docs/mcp/spec-refs/`. They are **never** imported by runtime code. Tests may use them as fixtures.

## Trust model

- We trust nothing the server sends. Every response is treated as adversarial input.
- We control everything we send: explicit byte-level requests, no library coercion in the way.
