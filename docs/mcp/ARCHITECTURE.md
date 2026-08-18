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

## Consent surface

An elicitation is where a server stops addressing the agent and addresses the
person operating it: URL mode sends a browser somewhere, form mode asks for
values to be typed. MST reads both and answers neither.

**What is declared.** A resolver-backed server will not describe the
elicitation it would raise unless the client declares the mode first - the
reference SDK checks the declaration and answers `-32021` instead. The two
routes are declared differently on purpose:

| Route | Declared | Why |
|---|---|---|
| 2026-07-28 | `elicitation: {form, url}` | the request arrives inside an `input_required` result; the server answers and moves on |
| 2025 line | `elicitation: {url}` | form mode there is a request the server blocks on, and MST never answers one; URL mode arrives as error `-32042` and costs nothing |

Sampling and roots stay undeclared: both ask the client to act.

**What is audited.** The address in URL mode and the schema in form mode, never
the exchange. Severity is spent only where a person could not have checked the
surface even in principle:

| Observation | Severity |
|---|---|
| credentials embedded ahead of the host | HIGH |
| cleartext scheme, off loopback | HIGH |
| bare IP host, off loopback | MEDIUM |
| secret named in a form property | HIGH |
| secret named only in a property description | MEDIUM |
| consent address leaves the scanned origin | INFO |

An off-origin consent URL is what an identity provider is, and http on loopback
is how a locally spawned server authorizes - a severity on either would put a
finding on every honest target. The name/description split exists because a
property name is chosen deliberately while a description is prose, and prose
says "no password is required" as readily as it asks for one.

Form mode is specified for non-sensitive input, so a schema collecting a
credential is a spec violation before it is a judgement call.
