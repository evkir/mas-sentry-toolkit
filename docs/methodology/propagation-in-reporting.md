# Propagation in Reporting

## Closing the silent gap between contamination detection and the report

### Abstract

Transitive injection propagation reconstructs how a poisoned directive
spreads across agents, and consume-edge inference gives each contaminated
agent a real onward blast radius even in a passive scan. Both land in the
ABFP scan output as a `propagation` block and a `propagation_summary`
header. But detection that never reaches the report is detection that never
happened: `mas-sentry report convert` read only the top-level `findings`
array and silently discarded both blocks. A CRITICAL verbatim relay that
crossed three agents was computed, scored, and then dropped on the floor of
every SARIF, HTML, Markdown, and JUnit report. This page describes how the
contamination surface is wired into the unified report pipeline.

---

### The gap

The ABFP scan writes a bespoke JSON document. Its `findings` array holds the
per-agent rogue-scan results; alongside it sit `propagation` (one entry per
contaminated agent: origin, chain, depth, tier, severity, taxonomy, and the
fused onward blast radius) and `propagation_summary` (contaminated count,
max chain depth, origins). The converter that turns scan JSON into polished
reports only ever looked at `findings`. Everything the propagation engine
produced lived in keys the converter did not read, so no report format
carried a single contamination finding.

---

### One mapping, two entry points

A contamination finding must look identical whether it was produced by a
live in-process scan or reconstructed from a saved JSON file on the CLI.
Rather than maintain two converters that could drift, there is a single
adapter - `from_propagation_finding` - that maps a `PropagationFinding` into
the unified `Finding` (module `abfp.propagation`, chain severity carried
through, and origin / contaminated agent / depth / tier / chain / onward
blast radius fused into evidence). The live scan path can call it directly.
`report convert` reads the serialized `propagation` block, rebuilds each
`PropagationFinding` from its JSON, and runs it through the same adapter.
The serialized block is exactly a serialized `PropagationFinding`, so this
is honest deserialization, not a parallel mapping - the two entry points
cannot diverge.

---

### What each format now carries

Once contamination findings join the unified list, the generic exporters do
the rest:

- **SARIF** emits a dedicated `abfp.propagation` rule. Its GitHub
  security-severity is band-anchored on the chain severity (a CRITICAL
  contamination lands in the 9.0-10.0 band), and the ASI08 Cascading Failure
  taxonomy plus the onward blast radius travel in the result properties, so
  code-scanning ranks a multi-hop relay above an isolated anomaly.
- **HTML** renders a distinct contamination-chain block - the path
  `origin -> ... -> target` with its depth and tier - separate from the raw
  evidence dump, next to the existing cascade blast-radius panel.
- **Markdown** carries a human-readable chain line and an onward-blast-radius
  line, suitable for pasting into an issue tracker or a bug-bounty report.
- **JUnit and JSON** carry the findings through their generic paths.

---

### Triage banner

The `propagation_summary` header is surfaced as a banner above the findings
list in both HTML and Markdown: how many agents were contaminated, the
deepest chain observed, and the origin agents the contamination seeded from.
It answers the first question a responder asks - how bad, how deep, from
where - before they read a single finding. When a scan found no propagation
the banner is omitted entirely, so a clean run stays clean.
