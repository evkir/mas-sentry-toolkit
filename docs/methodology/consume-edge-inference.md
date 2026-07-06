# Consume-Edge Inference

## Recovering the missing half of the topology in a passive scan

### Abstract

Cascade blast-radius answers the defender's sharpest question about a
contaminated agent: if this agent is hijacked, which downstream agents does its
output actually reach? The answer is a traversal over the publish/subscribe
topology - `agent -[publish]-> topic -[subscribe]-> agent`. But a passive MAS
listener sees only what is *published* on the bus; it never observes the
SUBSCRIBE control packets that tell it who *consumes* a topic. With no observed
subscribe edges the topic graph is all publishers and no consumers, every
traversal dead-ends at a topic, and `blast_radius` returns an empty reach. The
most valuable view in a live passive scan was, in effect, dead code.
Consume-edge inference recovers the missing half of the topology from evidence
the scan already collects.

---

### 1. The gap

In an active scan MAS-Sentry can enumerate subscriptions; in a passive scan it
cannot, and passive is the mode that matters for observing a production mesh
without touching it. The `TopicGraphBuilder` records a publish edge for every
observed message but has no `topic -> agent` edge to traverse, so the cascade
computed a topology-only blast radius that was always empty. Flagging an agent
as rogue while reporting that it reaches nobody is worse than silence: it reads
as a false all-clear on the one question that quantifies impact.

---

### 2. Inference from re-emission

The scan already reconstructs how injection directives spread across agents for
transitive propagation. That same evidence answers a consumption question. When
a downstream agent re-emits a directive first seen from an upstream source, the
downstream agent could only have obtained that content by *consuming* a topic
the source published it on. Re-emission is therefore proof of consumption, and
the source event pins the topic that was consumed.

The attribution is shared with the propagation graph - one walk over the
ordered injection events, two projections - so cascade and propagation can never
disagree about who relayed what. Two evidence tiers carry through:

- **verbatim** - a distinct agent later emits a payload whose hash matches an
  earlier injection-positive payload. Hash-anchored, high confidence.
- **directive** - a distinct agent later emits an injection carrying the same
  STRONG directive pattern a prior agent emitted. The instruction, not
  necessarily the bytes, crossed the boundary.

Each re-emission yields one inferred consume edge `(source_topic -> downstream
agent)`, attributed to the nearest prior distinct source, keyed and merged so
repeats collapse and verbatim outranks directive.

---

### 3. Inference is never dressed as observation

An inferred consume edge is a behavioral deduction, not a captured SUBSCRIBE,
and MAS-Sentry keeps that boundary explicit end to end:

- Inferred edges enter the topic graph under a distinct `subscribe-inferred`
  kind, separate from observed `subscribe`.
- An inferred edge never overwrites an observed subscribe (or an already-added
  inferred edge) for the same `(topic, agent)` - ground truth always wins.
- `blast_radius` splits its result: reach reachable over observed edges alone
  stays in `direct` / `transitive`, while reach that depends on an inferred
  edge is also listed in `inferred_direct` / `inferred_transitive`. An agent
  reachable both ways is credited as observed.

A report consumer can therefore trust `direct` as observed fact and read
`inferred_*` as a ranked hypothesis, rather than being handed a single blended
number that hides which is which.

---

### 4. Integration

During a passive ABFP scan the inferred consume edges are computed from the
captured injection events and fed into the topic graph immediately before it is
built, so the very same `cascade.blast_radius` that ran empty before now returns
a real downstream cone - direct consumers, the transitive contamination cone,
and their inferred provenance - fused into each rogue finding and each
propagation entry. The end-to-end passive path (MQTT loop through report) is
covered against a mocked broker, so the revival is verified through the real
entry point, not only in isolation.

---

### 5. Limitations

Inference is bounded by what re-emission can prove. A consumer that ingests a
directive but never re-emits it leaves no trace, so its consume edge is not
inferred - the reach reported is a lower bound, never an over-count. Nearest-
source attribution picks the most recent plausible origin topic; where several
upstream agents emitted the same STRONG pattern, the directive tier attributes
to the closest, which is a heuristic, not a proof of exact provenance. Verbatim
(hash-anchored) inference does not suffer this ambiguity. None of this replaces
an active subscription enumeration where scope permits one; it makes the passive
mode useful instead of blind.
