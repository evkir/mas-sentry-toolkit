# Threat Modeling

MAS-Sentry tags every finding with the vocabularies a reader needs to route it:
what agentic risk class it belongs to, what weakness it is, what security
property it breaks, and - where one fits cleanly - what adversary technique it
corresponds to.

## Where tags come from

There is no threat-modeling package and no mapper that walks finished findings
through a lookup table. **Tags are attached by the check that produced the
finding**, at the point where the context justifying them is still in hand.

A detector knows things a later pass cannot recover. It knows whether a probe
confirmed the unsafe behaviour or merely observed a symptom, whether the target
refused or answered, and which specific field carried the payload. A mapper
running over a finished list sees a title and a module name and has to guess.
The guessing is where false taxonomy comes from, so it does not exist here.

Tags travel on `Finding.tags` into Markdown, HTML and SARIF without further
processing.

## The four vocabularies

| Prefix | Vocabulary | Example |
|---|---|---|
| `ASI##_` | OWASP Agentic Top 10 (2026) | `ASI01_Goal_Hijack` |
| `CWE-` | MITRE CWE | `CWE-1427` |
| `STRIDE_` | STRIDE | `STRIDE_Tampering` |
| `AML.T` | MITRE ATLAS | `AML.T0051` |

## When a tag is left off

**A tag is attached only where the match is clean.** An absent tag is a
statement, not an oversight:

- Argument injection into a tool call carries CWE-77 and `STRIDE_Tampering` but
  no ATLAS technique, because no published technique describes it without
  stretching the definition.
- An unauthorized-cancel probe carries CWE-862 and `STRIDE_Elevation_Of_Privilege`
  but no ASI code, because none of the ten categories covers missing
  authorization on a task operation.
- A probe that ran and held is recorded without any vulnerability class at all.
  Tags attach when a probe **fails**, not when it merely executes.

Only four ATLAS techniques are used across the whole codebase - `AML.T0051`,
`AML.T0080`, `AML.T0048`, `AML.T0110` - because those are the four with
unambiguous matches. Inventing a fifth would make the reports look more rigorous
and be less true.

## STRIDE in a multi-agent context

| Category | Example in a MAS deployment | Detected by |
|---|---|---|
| **Spoofing** | Anonymous broker access, client-id impersonation, agent-card identity claims | `mqtt.anonymous_access`, ABFP impersonation scoring, A2A card audit |
| **Tampering** | Retained-message poisoning, tool-descriptor rug-pull, poisoned resource content | `mqtt.retained_injection`, `mcp.tool_rug_pull`, `mcp.resource_content` |
| **Repudiation** | Actions taken by an agent with no attributable record | Not detected - see below |
| **Information disclosure** | `$SYS` telemetry to anonymous readers, wildcard traffic exposure, exfiltration beacons | `mqtt.sys_exposure`, `mqtt.topic_exposure`, `mqtt.retained_exfil` |
| **Denial of service** | Message floods, unbounded tool output, resource exhaustion | ABFP burst scoring, `agentic/resource_exhaustion.py` |
| **Elevation of privilege** | Topic ACL bypass, delegation-mesh escalation, unauthorized task cancel | A2A mesh audit, A2A probes |

**Repudiation has no detector.** Untraceable actions are covered
statically in `agentic/action_audit.py` under the MST-only
`MST_Untraceable_Actions` tag - the published 2026 list has no category for
them - but no protocol scan currently
establishes whether an agent actions are attributable on the wire. The row is
kept in this table because the category is real; claiming coverage for it would
not be.

## CVSS

Not implemented, deliberately. Severity here reports what a check established -
confirmed exploitation, confirmed weakness, signal needing judgement, or an
unassessed surface - and that ordering is what an operator triages on. A CVSS
vector expresses something else and would have to be invented per finding to
produce a number, which is precision without accuracy.

## Reading severity

See the "Reading a report" section of the project README for what each level
means, and for the gap findings that mark the limits of a scan rather than the
health of a target.
