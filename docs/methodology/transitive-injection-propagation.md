# Transitive Prompt Injection Propagation

## Tracking an injected directive as it spreads across the agent bus

### Abstract

The passive `injection` dimension flags an agent that *emits* an indirect-
prompt-injection directive. It does not answer the multi-agent question that
makes MAS uniquely fragile: once a directive lands in one agent, does it
*spread*? In a Multi-Agent System agents exchange work over legitimate
channels, and a hijacked instruction rides those channels like an infection -
agent B ingests A's poisoned output, treats it as a trusted internal message,
re-emits the directive, and contaminates B's own downstream consumers. The
attack surface grows multiplicatively with each hop. MAS-Sentry reconstructs
this spread passively, from observed re-emission, and scores it as a
cascading failure distinct from any single agent's anomaly.

---

### 1. Threat model

A single injection into one agent does not stay local. If A is compromised and
emits manipulated output that B consumes, B follows the injected instructions
because they arrived from a *trusted* internal peer - the same reason the
directive is dangerous is the reason it propagates. Left unmodeled, this looks
like several independent single-agent hits; in reality it is one origin and a
chain of victims. Two properties matter that per-agent scoring cannot express:

- **Origin vs. victim.** Which agent introduced the directive, and which merely
  relayed something they ingested.
- **Depth.** How many agent boundaries the directive survived - a proxy for how
  far trust was abused and how large the blast surface became.

---

### 2. Detection from re-emission

MAS-Sentry never assumes propagation from topology alone (who *could* consume a
topic). It requires evidence that a directive actually crossed a boundary: a
later emission by a *distinct* agent carrying a directive an earlier agent
emitted. Two tiers are ordered by confidence:

- **verbatim** - a distinct agent later emits a payload whose hash matches an
  earlier injection-positive payload. The poisoned content was forwarded
  intact. Hash-anchored, low false-positive.
- **directive** - a distinct agent later emits an injection carrying the same
  STRONG directive pattern a prior agent emitted. The instruction, not
  necessarily the bytes, crossed the boundary.

Each re-emission is attributed to its *nearest* prior distinct source, so the
result is an infection chain rather than a dense graph. Edges always run from an
earlier emission to a later one; an edge that would close a cycle is dropped, so
the graph is a DAG and depth is well defined. Only injection-positive events are
recorded - patterns plus a payload hash, never the payload itself - so memory
stays bounded regardless of traffic volume.

---

### 3. Severity by depth and tier

Contamination severity is computed directly from the chain, not routed through
the weighted-mean anomaly score - a chain-level property would be diluted by an
agent's unrelated topology dimensions. The ladder:

| Evidence                          | Severity |
|-----------------------------------|----------|
| directive, single hop (depth 1)   | HIGH     |
| directive, two or more hops       | CRITICAL |
| verbatim relay, any depth         | CRITICAL |

An origin agent carries no propagation finding - it is already flagged by the
per-agent `injection` dimension as an emitter. Every non-origin agent on a
chain gets a finding tagged `ASI01_Goal_Hijack`, `ASI05_Cascading_Failure`,
`CWE-1427`, `STRIDE_Tampering`, and `AML.T0051`. ASI05 is what separates a
propagated directive from a merely-emitted one.

---

### 4. Report output

`run_abfp_scan` feeds the captured injection events through the propagation
graph and writes a `propagation` block: per contaminated agent the origin, the
chain that reached it, the depth, the worst inbound tier, the severity, the
taxonomy, and - fused with cascade - that agent's onward blast radius (who it
can further infect). A `propagation_summary` header gives the contaminated
count, maximum depth, and the set of origins for fast triage.

---

### 5. Limitations

- Directive-tier attribution keys on shared STRONG patterns; two agents that
  independently emit the same common directive will be linked even without a
  real causal hop. Verbatim tier (hash match) does not have this ambiguity.
- Nearest-source attribution reconstructs one plausible chain, not necessarily
  the true infection path when several upstream emitters share a pattern.
- Detection is bounded by what the passive collector observes; an out-of-band
  relay channel MAS-Sentry cannot see will not appear in the graph.

---

### 6. Related

- [Indirect Prompt Injection](indirect-prompt-injection.md) - single-agent
  directive detection this builds on.
- [ABFP](ABFP.md) - the agent-behavior fingerprinting scan that hosts it.
