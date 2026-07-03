# A2A Protocol Scanning

## Discover, audit, and probe Agent-to-Agent endpoints

### Abstract

The Agent-to-Agent (A2A) protocol lets autonomous agents advertise their
capabilities through a published **AgentCard** and accept delegated work as
tasks. The protocol deliberately leaves trust, authentication, and transport
security to the implementer - which is exactly where deployments go wrong.
MAS-Sentry scans an A2A endpoint end to end: it discovers the AgentCard,
audits it passively for insecure configuration and embedded injection, and -
on explicit opt-in - runs live probes that submit tasks to observe how the
agent actually behaves. Every result is mapped to the unified Finding, so an
A2A scan lands in the same HTML / Markdown / SARIF / JUnit pipeline as the
MCP and ABFP verticals.

---

### 1. Threat model

An A2A agent is reachable at a base URL exposing `/.well-known/agent.json`.
Three classes of weakness matter:

- **Card configuration.** Missing or `none` authentication lets any caller
  submit tasks; uncapped streaming invites resource exhaustion; unsigned push
  callbacks can be spoofed; a cleartext (`http://`) endpoint invites card
  tampering in transit; an oversized skill surface widens the attack surface.
- **Card poisoning.** The AgentCard description and skill fields are ingested
  by an orchestrator's LLM when it reasons about which agent to delegate to.
  An injection directive hidden there hijacks that routing decision - the same
  class MAS-Sentry detects in MCP tool descriptors and live agent traffic.
- **Runtime behavior.** Whether the endpoint enforces task-id ownership,
  rejects cancellation of tasks it did not issue, and treats task content as
  data rather than instructions can only be established by interacting with it.

Passive checks cover the first two; the third requires active probing.

---

### 2. Passive audit

`audit_agent_card` inspects the discovered card and never submits a task. It
emits a `CardFinding` per weakness, each carrying the four-lens taxonomy so
SARIF ranks it and cross-taxonomy filters see it:

| Finding                     | Severity | ASI  | CWE      | STRIDE               |
|-----------------------------|----------|------|----------|----------------------|
| No / `none` authentication  | HIGH     | ASI03 | CWE-306  | Spoofing             |
| Streaming without limits    | MEDIUM   | ASI07 | CWE-400  | Denial of Service    |
| Unsigned push callbacks     | MEDIUM   | ASI03 | CWE-345  | Spoofing             |
| Excessive skill surface     | LOW      | ASI02 | CWE-272  | Elevation of Privilege |
| Cleartext transport         | MEDIUM   | -    | CWE-319  | Tampering            |
| Agent Card Poisoning        | HIGH     | ASI01 | CWE-1427 | Tampering (AML.T0051) |

Card poisoning reuses the shared `injection_scan` primitive, so any pattern
added for MCP or live-traffic detection immediately hardens the card audit too.

---

### 3. Active probes

Probes are gated behind `--active` and only run against endpoints in scope
(localhost / lab targets, or an explicit `--confirm-scope`). Each submits a
task and classifies the response as safe or unsafe. Taxonomy attaches only
when the probe **fails** - a probe that holds is recorded INFO without a
vulnerability class, keeping the report honest.

| Probe                | Unsafe means                        | Severity | Taxonomy on failure                       |
|----------------------|-------------------------------------|----------|-------------------------------------------|
| task-id collision    | Two tasks accepted under one id     | HIGH     | ASI03 / CWE-345 / Spoofing                |
| unauthorized cancel  | A foreign task can be cancelled     | HIGH     | CWE-862 / Elevation of Privilege          |
| indirect injection   | A canary directive is echoed back   | CRITICAL | ASI01 / CWE-1427 / Tampering / AML.T0051  |

The indirect-injection probe embeds a random canary token inside an injected
instruction and inspects the returned artifacts: if the token comes back, the
agent executed the injected directive rather than treating the task content as
data. `unauthorized-cancel` is deliberately left without an ASI tag - a missing
authorization check has no clean agentic-top-10 slot, so only CWE and STRIDE
are asserted rather than forcing a poor fit.

---

### 4. Running a scan

```bash
# Passive: discover + audit the card only (no task submission)
mas-sentry a2a scan -t http://localhost:9000

# Active: also run the live probes (submits tasks)
mas-sentry a2a scan -t http://localhost:9000 --active

# Non-lab target: authorisation is required even for the passive fetch
mas-sentry a2a scan -t https://agent.example.com --active --confirm-scope
```

Scope is enforced centrally by the A2A client on construction: any target
outside the lab allowlist requires `--confirm-scope`, covering the passive
card fetch as well as the probes. The scan writes unified findings to
`reports/a2a.json`, which feeds `mas-sentry report convert` for HTML, Markdown,
SARIF, or JUnit without any re-adaptation.

---

### 5. Limitations

- Card poisoning detection is signature-based over the shared pattern set;
  novel obfuscations outside the set are not caught.
- Probes establish behavior for the specific task shapes they submit; an agent
  may enforce ownership on some code paths and not others.
- A single canary echo proves an injection vector executed, not that a
  downstream consumer was compromised - the CRITICAL rating reflects the direct
  observation, not a full impact assessment.

---

### 6. Related

- [Indirect Prompt Injection](indirect-prompt-injection.md) - the same
  directive class detected in live agent traffic and MCP descriptors.
- [Threat Modeling](threat-modeling.md) - the broader MAS threat surface.
