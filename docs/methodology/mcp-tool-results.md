# MCP Tool Results and Resource Content

Two MCP surfaces were being read incorrectly, or not at all. Both cost real
detections against servers that behave exactly as the specification tells them
to, which is the worst kind of blind spot: the better the target implements the
protocol, the less the scanner saw.

## Tool results are content blocks, not strings

A `tools/call` result is a list of typed content blocks. Text sits under `text`;
images and audio arrive base64-encoded under `data`; an embedded resource nests
its own text or blob. Stringifying the raw result object and matching a
substring against it fails twice over:

- **Truncation cuts the payload.** A Python repr leads with dict scaffolding, so
  a fixed prefix spends its budget on `{'content': [{'type': 'text', ...` before
  reaching the content. An indicator further in is simply not seen.
- **Base64 hides everything.** Content delivered as an image or resource blob is
  encoded on the wire. No plaintext indicator can ever match it.

The second failure is the same class the A2A artifact reader closed: a scanner
that greps an encoded payload finds nothing and calls the target clean.
Extraction now decodes each block, so matching runs on what a reader would see,
and truncation applies only to the evidence recorded in a finding.

## Tool errors do not arrive as protocol errors

MCP deliberately splits errors in two:

| Layer | Carried as | Example |
|-------|-----------|---------|
| Protocol | JSON-RPC `error` | unknown tool, malformed request |
| Tool | successful response with `isError: true` | fetch blocked, path rejected |

The split exists so the model can see a tool failure and self-correct - a
protocol error never reaches it. For a scanner the consequence is sharp: a
server that **firmly refuses** a probe payload returns a successful JSON-RPC
response. Checking only the `error` field, that refusal falls through to
indicator matching, matches nothing, and is discarded as an unremarkable
success.

A properly guarded tool therefore looked identical to a silent one. All probes
now treat a tool-level error as a denial alongside a protocol-level one.

## Resource content was never read

Resources were enumerated and never fetched, leaving their contents the one
agent-facing MCP surface with no audit at all - and the wrong one to skip. A
resource is what an agent pulls into its own context on its own initiative,
which makes a poisoned resource the textbook indirect-injection vector: the
instruction does not come from the user, it arrives with data the agent fetched
and trusted.

Reading is safe here in a way that calling arbitrary tools is not.
`resources/read` returns application-controlled data with no side effects by
design, whereas invoking an unknown tool could write, delete or spend. The audit
reads what a client would read and nothing more.

Each resource is scanned on two axes with the shared core primitives:

- `injection_scan` - hidden directives arriving in the content (the cause)
- `output_exfil` - auto-fetch beacons embedded in it (the effect)

A resource carrying a beacon leaks on render; one carrying a directive is the
ingestion half of the same attack. HIGH is reserved for unambiguous signal - a
strong injection pattern such as invisible characters, an explicit override or a
tool-call hijack, or a concrete external beacon. Softer phrasing matches alone
stay MEDIUM, because they are a lead rather than a verdict.

```bash
# Resource content is part of a full scan, or can be run alone
mas-sentry mcp scan --target http://localhost:3000 --checks resources
```

Findings flow through `report convert` like every other check.

## What this does not cover

- **Tool outputs at large.** Only tools the existing probes already invoke are
  read. Calling arbitrary tools to inspect their output is not something a
  scanner should do uninvited, since an unknown tool may have side effects.
- **Prompt templates.** `prompts/get` renders a template with arguments and is
  not yet audited.
- **Resources requiring arguments.** Only resources returned by `resources/list`
  are read; templated resource URIs are out of scope for now.
