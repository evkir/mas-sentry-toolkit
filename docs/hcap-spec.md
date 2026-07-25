# HCAP — Hierarchical Capability and Attestation Protocol

**Specification draft v0.1** — research preview
**Author:** Evgeny Kiriyak (evkir) — MASec Lab
**Status:** Working Draft
**Last updated:** 2026-05-08

---

## 1. Abstract

HCAP is a security protocol for Multi-Agent Systems (MAS) that addresses three problems simultaneously:

1. **Blast radius containment** — compromising one agent does not grant access to others
2. **No single point of failure** — there is no "king"; the coordinator is re-elected
3. **Edge-deployable** — works on embedded devices without heavy sandboxing

The protocol is built on 4 layers: Identity (L1), Capability (L2), Quorum (L3), Behavioral (L4). Each layer addresses its own threat class and operates independently when others fail.

This document specifies the protocol design, message formats, state machines, and security properties. A reference implementation is provided in `mas_sentry/protocols/hcap/`.

---

## 2. Threat Model

### 2.1 Assumptions

- The attacker can compromise at most ⌊(N-1)/3⌋ agents (classic BFT bound)
- The attacker has full control over a compromised agent: keys, code, behavior
- The network may be partially asynchronous (delays exist, but no permanent partition)
- Cryptographic primitives (Ed25519, SHA-256) are considered secure

### 2.2 Out of Scope

- Physical destruction of an agent (this is resilience, not security)
- Attacks on the LLM itself (model jailbreak — separate layer)
- Cold-start without bootstrap quorum (requires initial trust ≥ K honest agents)

### 2.3 In-Scope Attacks

| ID | Attack | Defended by |
|----|--------|-------------|
| T1 | Identity spoofing | L1 |
| T2 | Replay attack | L1 |
| T3 | Out-of-scope command | L2 |
| T4 | Privilege escalation | L2 + L3 |
| T5 | Coordinator hijack | L3 |
| T6 | Sybil onboarding | L3 |
| T7 | Behavioral drift / insider attack | L4 |
| T8 | Cascading injection | L2 + L4 |

---

## 3. Architecture

### 3.1 Layer Stack

```
┌─────────────────────────────────────────┐
│  L4: BEHAVIORAL ATTESTATION (ABFP+)     │  ← anomaly detection
├─────────────────────────────────────────┤
│  L3: QUORUM CONSENSUS (BFT)             │  ← leader election, isolation
├─────────────────────────────────────────┤
│  L2: ROLE-BASED CAPABILITIES            │  ← what an agent CAN do
├─────────────────────────────────────────┤
│  L1: IDENTITY + CRYPTO                  │  ← who is this agent
└─────────────────────────────────────────┘
              ↓
       Transport (MQTT / AMQP / A2A)
```

### 3.2 Agent Types

```
NORMAL_AGENT      — performs tasks, has 1 or more roles
COORDINATOR       — elected, term-limited (T_term)
SENTINEL          — read-only observer, can isolate
BOOTSTRAP_AGENT   — initial trust anchor (offline keys)
```

A single physical agent may play multiple roles simultaneously, but **never coordinator + sentinel** (separation of duties).

---

## 4. Layer 1 — Identity

### 4.1 Agent identifier

```
AgentID = "agent_" + first16hex( sha256(public_key) )
```

Example: `agent_7a9f2c81d4e5b603`

### 4.2 Message format

All inter-agent messages use JSON with mandatory fields:

```json
{
  "v": 1,
  "from": "agent_7a9f2c81d4e5b603",
  "to": "agent_3b1e8f72c9d0a456 | broadcast | role:repair_drone",
  "ts": 1746732000,
  "nonce": "01HX7QKZRJ8M...",
  "type": "command | inform | query | attest | alert",
  "role_claim": "delivery_drone",
  "payload": { },
  "sig": "ed25519:..."
}
```

### 4.3 Receiver-side mandatory checks

```
1. signature_valid(sig, payload, public_key_of(from))   → else DROP
2. abs(now() - ts) < CLOCK_SKEW_MAX (default 30s)       → else DROP
3. nonce not in seen_nonces (replay window 60s)         → else DROP
4. from in registry AND not in isolated_set             → else DROP
5. role_claim in registered_roles_of(from)              → else DROP
```

If any check fails, the message is dropped and the event is logged.

### 4.4 Forward secrecy

Each agent stores a **long-term identity key** (offline where possible) and a **session key** that ratchets every T_ratchet (recommended: 1 hour). Compromise of the session key does not grant access to past messages.

---

## 5. Layer 2 — Capabilities

### 5.1 Capability Manifest

On onboarding, each agent publishes a signed manifest:

```json
{
  "agent_id": "agent_7a9f2c81d4e5b603",
  "roles": ["delivery_drone"],
  "capabilities": [
    "read_route",
    "fly_path",
    "drop_payload",
    "report_status"
  ],
  "constraints": {
    "max_altitude_m": 120,
    "geofence": "zone_A",
    "max_payload_kg": 5
  },
  "issued_at": 1746732000,
  "expires_at": 1746818400,
  "issuer_quorum": [
    "agent_aaaa.....", "agent_bbbb.....", "agent_cccc....."
  ],
  "issuer_sigs": ["...", "...", "..."]
}
```

**The manifest is signed by K issuers from the quorum** (see L3). Self-signing is not allowed.

### 5.2 Policy Engine

When a message with `type=command` arrives, the receiving agent checks:

```
1. Extract requested_action from payload
2. requested_action ∈ capabilities_of(sender) ?
3. requested_action ∈ allowed_actions_for_my_role ?
4. Constraints not violated (e.g. cannot request altitude above max)?
5. If all YES → execute. Otherwise → DROP + alert sentinels
```

### 5.3 Pre-defined roles (drone swarm reference)

```yaml
delivery_drone:
  can: [read_route, fly_path, drop_payload, report_status, request_repair]
  cannot: [modify_swarm_config, repair_other, command_others]

repair_drone:
  can: [read_telemetry, dock_to_drone, replace_module, report_repair]
  cannot: [deliver_payload, command_others, modify_routes]

coordinator:
  can: [assign_tasks, request_repair, broadcast_route_update,
        propose_isolation, propose_election]
  cannot: [direct_code_modify, override_safety, sign_capability_manifests_alone]
  term_limited: true
  term_seconds: 600

sentinel:
  can: [observe_all_channels, raise_alert, vote_isolation]
  cannot: [send_commands, modify_state, become_coordinator]
```

### 5.4 Cascading injection defense (L2)

Agents **never** treat a payload from another agent as "instructions for themselves", regardless of sender role. A message of type `inform` is data, not instructions. Only `command` is subject to execution, and only within capability scope.

This is a formal barrier against ACI: even if the payload contains "ignore previous instructions", the policy engine does not parse the payload as instructions. It looks only at `requested_action` and verifies it against capabilities.

---

## 6. Layer 3 — Quorum

### 6.1 Purpose

Decisions that should not be made by a single agent:
- Onboarding a new agent
- Isolating a suspicious agent
- Electing/re-electing the coordinator
- Updating policy/capabilities

### 6.2 Quorum Operation Protocol

Every quorum operation = K-of-N voting. By default **K = ⌊2N/3⌋ + 1** (BFT-safe).

```
1. PROPOSE:    initiator sends {operation, target, reason, nonce}
2. PRE-VOTE:   agents validate the proposal, send {accept|reject}
3. COMMIT:     if ≥ K accepts within T_quorum → operation applies
4. APPLY:      all agents update local state and sign the result
```

### 6.3 Leader Election

The coordinator is elected for T_term seconds. Default: 600 (10 min).

Algorithm (simplified Raft for embedded):

```
1. Each eligible agent has a randomized election_timeout (150–300ms)
2. If timeout expires without heartbeat from current coordinator:
   → agent becomes candidate, sends RequestVote with term+1
3. On receiving majority votes → becomes coordinator
4. Every T_heartbeat (1s) sends heartbeat signed with current term
5. After T_term → mandatory re-election (even if alive)
```

**Critical:** the coordinator cannot appoint a successor. Only elections.

### 6.4 Sybil resistance

A new agent cannot enter the quorum until:

```
1. Manifest is signed by K_bootstrap from existing agents
2. Behavioral baseline (L4) collected for ≥ T_baseline (default 24h)
3. Behavioral attestation signed by K_quorum neighbors
```

The attacker must compromise K honest agents to add one fake. For N=10, K=7 — practically impossible if at least 7 are honest initially.

---

## 7. Layer 4 — Behavioral Attestation (ABFP+)

### 7.1 Behavioral Fingerprint

For each agent, periodically (T_fp = 5 min) collect:

```json
{
  "agent_id": "agent_7a9f...",
  "window_start": 1746732000,
  "window_end": 1746732300,
  "topic_graph": {
    "delivery_route": 42,
    "status_report": 15
  },
  "timing_stats": {
    "msg_per_sec_mean": 0.8,
    "msg_per_sec_p99": 2.1,
    "burst_count": 3
  },
  "payload_stats": {
    "len_mean": 256,
    "len_p99": 1024,
    "entropy_mean": 4.2
  },
  "tool_usage": {
    "fly_path": 12,
    "drop_payload": 2
  },
  "fsm_transitions": [
    "idle->planning", "planning->flying", "flying->delivering"
  ]
}
```

### 7.2 Fingerprint signing

```
sig = Ed25519.sign(privkey_agent, hash(fingerprint))
```

Published in registry. Neighbors (K of N) sign **co-attestation**:

```
co_attestation = Ed25519.sign(privkey_neighbor, hash(fingerprint))
```

This provides resilience: the attacker who hijacked an agent cannot "rewrite" its history — it is fixed by neighbors.

### 7.3 Anomaly detection

Sentinel compares the current fingerprint against the baseline (sliding window of last N fingerprints):

```
score = weighted_distance(current, baseline)
if score > THRESHOLD:
   raise_alert(agent_id, evidence=[current, baseline, score])
```

Specific metrics:
- **Topic shift**: KL-divergence on topic distribution
- **Timing anomaly**: z-score on msg-per-sec
- **Payload mismatch**: divergence in entropy/length distribution
- **FSM violation**: a transition not present in the model graph

### 7.4 Reverse channel

Sentinels communicate over a dedicated channel:

```
Topic: hcap/sentinel/alerts (write: only sentinel role)
Topic: hcap/sentinel/quorum (write: only sentinel role)
```

Worker agents have no write access on this channel at the broker policy level (MQTT ACL). A compromised delivery_drone cannot suppress alerts.

---

## 8. State Machines

### 8.1 Agent lifecycle

```
        BOOTSTRAP_REQUESTED
              │
              ▼
     ┌──── PROBATION ────┐    (baseline collection, T_baseline)
     │      │            │
     │      ▼            │
     │  ATTESTED ────────┘    (K-of-N signed)
     │      │
     │      ▼
     │   ACTIVE ◄──────────┐
     │      │              │
     │      │ alert        │ recover
     │      ▼              │
     │   SUSPECT ──────────┘
     │      │
     │      ▼ (quorum vote)
     └─► ISOLATED
              │
              ▼
          REVOKED
```

### 8.2 Coordinator lifecycle

```
   FOLLOWER ──timeout──► CANDIDATE ──majority──► LEADER
       ▲                    │                       │
       │                    │ no majority           │ term expired
       └────────────────────┴───────────────────────┘
```

---

## 9. Security Properties (formal)

| Property | Guarantee | Condition |
|----------|-----------|-----------|
| **Authenticity** | A message from X is really from X | privkey_X not leaked |
| **Authorization** | X can only do what is in its capabilities | Policy engine on each node |
| **Blast radius** | Compromise of X = access only to caps(X) | Capabilities not self-signed |
| **No SPOF** | Coordinator failure does not bring down the system | f < N/3 honest |
| **Sybil resistance** | A new agent = K honest signatures | K ≤ N - f |
| **Forward secrecy** | Old messages unreadable on session-key leak | Ratcheting every T_ratchet |
| **Detection** | Anomalous behavior is detected | Sentinels online, baseline exists |

---

## 10. Performance & Edge Considerations

| Operation | Cost | Edge-friendly? |
|-----------|------|----------------|
| Ed25519 sign/verify | ~0.1ms on ARM Cortex-M4 | ✅ |
| SHA-256 fingerprint | <1ms on 1KB data | ✅ |
| BFT vote round | 3–5 messages × N | ✅ for N≤50 |
| Behavioral collection | ~10KB RAM per agent | ✅ |
| Sentinel monitoring | separate device | ✅ (off-drone) |

**No containers. No VMs. Only Ed25519 + SHA-256 + a policy engine.**

---

## 11. Open Issues

Questions to address in v0.2:

1. **Cold start**: how to bootstrap a swarm with no existing agents?
2. **Network partition**: split-brain between two drone groups
3. **Re-baseline**: how to legitimately update the baseline without false-isolate?
4. **Post-quantum**: migration from Ed25519 → ML-DSA when NIST finalizes
5. **Cross-MAS federation**: communication between different HCAP domains

---

## 12. References

1. OWASP. Top 10 for Agentic Applications 2026. (released 2025-12-09).
2. ACIArena: Toward Unified Evaluation for Agent Cascading Injection. arXiv:2604.07775.
3. Multi-Agent Systems Execute Arbitrary Malicious Code. OpenReview, 2025.
4. Sentinel Agents for Secure and Trustworthy Agentic AI in Multi-Agent Systems. arXiv:2509.14956.
5. MAScope: Beyond Input Guardrails. arXiv:2603.04469.
6. Security Considerations for Multi-agent Systems. arXiv:2603.09002.
7. PoisonedRAG. USENIX Security 2025.
8. FIPA ACL Specification. IEEE FIPA.
9. OWASP NHI Top 10 — Non-Human Identities.
10. Raft Consensus Algorithm — Ongaro & Ousterhout, 2014.

---

## License

This specification is released under CC-BY-4.0. The reference implementation is MIT.

## Contact

Open an issue with `[HCAP]` in the title at:
https://github.com/evkir/mas-sentry-toolkit
