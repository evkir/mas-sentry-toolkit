# Coordination Side-Channel Detection

## What this is not

This is **not** a collusion detector, and the distinction is the whole point of
the page.

State-of-the-art collusion detection reads model activations: the 2026 NARCBench
work aggregates per-agent deception probes across interacting agents and reports
strong separation, but it needs access to the models' internal representations.
A network scanner has none of that.

Worse for the naive approach, plain-text monitoring is theoretically defeated
against steganographic collusion. Schemes exist that are computationally
indistinguishable from good-faith communication, and an LLM judge watching the
traffic cannot separate collusive from ordinary exchanges. Any tool that claims
to read messages off a bus and tell you agents are colluding is overselling.

What a passive observer **can** do is what the same literature points to as the
remaining avenue: treat coordination as a side channel and measure its
consequences rather than its content.

## The signal

If agent B systematically publishes shortly after agent A, the two are coupled
in time, whatever their payloads say. Content can be encrypted, encoded, or
perfectly innocuous; the timing relationship survives.

Coupling on its own is not suspicious. A pipeline agent answering its upstream
is the system working correctly, and most of a healthy mesh is exactly that. The
interesting case is coupling the topology does not account for: a pair locked in
time with **no observed publish/consume path between them**. Those two agents
are coordinating through a channel this scan cannot see. That is a lead to
investigate, not a verdict to report to a client.

## Method

For an ordered pair (A, B), the raw statistic is the fraction of A events
followed by a B event inside a response window.

That number alone is worthless, because the obvious confounder scores high:
two agents on the same cron timer will appear tightly coupled while coordinating
nothing at all. So the statistic is standardised against a **circular-shift
surrogate null**. Shifting B's timeline preserves its own cadence, burstiness and
rate exactly, and destroys only its phase relationship with A. The reported `z`
is how many surrogate standard deviations the real coupling exceeds that null.

A z-effect is used rather than a permutation p-value on purpose: a rank-based
p-value has a hard resolution floor of `1/(K+1)`, and with the pair counts a mesh
produces, no practical surrogate count can push that floor under a
multiple-comparison threshold. The standardised effect has no such ceiling.

Measured on synthetic meshes:

| Case                          | z     |
|-------------------------------|-------|
| Clean 380-pair mesh (largest) | 2.94  |
| Shared timer, same period     | 1.9   |
| Partial coupling (40%)        | 9.5   |
| Full response coupling        | 24.9  |

The null measures as N(0,1) to two decimals, and the six-sigma default sits in
the gap between the noise ceiling and the weakest real signal.

## Limits

Every one of these fails toward **silence**, not toward a false accusation. For a
pentest deliverable that is the correct direction to be wrong in.

- **Two strictly periodic agents.** If both sides are rigidly periodic, a
  circular shift cannot break their alignment, so genuine coupling is
  mathematically indistinguishable from a shared timer. Not reported.
- **Long response lags.** The statistic looks at the next target event, so a
  reply arriving after the target's typical inter-publish interval is not seen.
- **Oversized windows.** A response window wider than the target cadence
  self-cancels: the null rises to meet the observation and the effect collapses.
- **Sparse traffic.** Below the minimum event count the surrogate null is too
  coarse to trust, and the pair is skipped rather than guessed at.
- **Large meshes.** Pair count grows quadratically; an oversized mesh is refused
  outright instead of stalling the scan.
- **Steganographic collusion.** Not detectable here, by construction. See above.

## Output

Findings land in a `coordination` section of the ABFP report, as pair evidence
rather than a per-agent score:

```json
{
  "coordination": [
    {
      "source": "fleet_lead_a1",
      "target": "fleet_echo_b2",
      "z": 24.9,
      "observed": 1.0,
      "null_mean": 0.218,
      "events": 120
    }
  ]
}
```

The signal belongs to the relationship, not to either agent alone, so folding it
into one agent's anomaly score would misattribute it. `observed` and `null_mean`
ship alongside `z` so the reader can judge the effect rather than trust a label.

Taxonomy: CWE-514 (covert channel) / STRIDE Information Disclosure / ASI07.
No ATLAS technique is asserted - no clean match exists for a timing side channel
between agents.
