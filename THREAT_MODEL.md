# Threat Model — MAS-Sentry-Toolkit

Two frameworks in parallel: **ASI01–ASI10** (OWASP Agentic AI Top 10, Dec 2025) and **STRIDE** at the agent-interaction layer (original ABFP contribution).

## 1. Classical MAS messaging (MQTT / AMQP)

| Threat | STRIDE | Module | Technique |
|---|---|---|---|
| Anonymous broker access | Spoofing | `protocols/mqtt/auth` | Unauth `CONNECT` probe |
| Credential brute-force | Spoofing | `protocols/mqtt/auth` | Wordlist + rate-aware attack |
| Retained-message poisoning | Tampering | `protocols/mqtt/exploits/retained` | Inject malicious retained payload |
| Will-message hijack | Tampering | `protocols/mqtt/exploits/will` | Replace LWT on disconnect |
| AMQP dead-letter abuse | Tampering | `protocols/amqp/exploits/dlq` | Routing-key brute-force into DLQ |
| Topic-tree enumeration | Information Disclosure | `protocols/mqtt/walker` | `$SYS` + wildcard scan |
| Broker DoS via fuzzed CONNECT | Denial of Service | `protocols/mqtt/fuzzer` | Malformed packet generator |

## 2. OWASP Agentic Top 10 (2026) coverage

### ASI01 — Agent Goal Hijack
- **Module:** `agentic/goal_hijack`
- **Technique:** Inject indirect-prompt-injection payloads via tool outputs / RAG / email / calendar invites; detect divergence between stated goal and executed plan.
- **Real-world ref:** EchoLeak (Microsoft 365 Copilot, 2025).
- **STRIDE:** Tampering + Elevation of Privilege.

### ASI02 — Tool Misuse & Exploitation
- **Module:** `agentic/tool_misuse`
- **Technique:** Catalogue of destructive tool combinations; out-of-scope tool invocation; argument-injection probes.
- **Real-world ref:** Amazon Q destructive-command incident (2025).

### ASI03 — Identity & Privilege Abuse
- **Module:** `agentic/identity_abuse`
- **Technique:** Agent-token replay; delegation-chain validation (RFC 8693); cross-agent privilege diff.

### ASI04 — Memory Poisoning
- **Module:** `agentic/memory_poisoning`
- **Technique:** Long-horizon drift detection across vector-store / conversation memory; canary-fact monitoring.
- **Real-world ref:** Procurement-agent fraud case (3-week memory poisoning, 2025).

### ASI05 — Cascading Failure
- **Module:** `agentic/cascade`
- **Technique:** Multi-agent failure-propagation tracer; circuit-breaker absence detection.

### ASI06 — Untraceable Actions
- **Module:** `agentic/action_audit`
- **Technique:** OpenTelemetry hook; missing-trace detection on tool calls; log-tamper canaries.

### ASI07 — Resource Exhaustion
- **Module:** `agentic/resource_exhaustion`
- **Technique:** Token-bomb prompts; infinite-loop / reflection-attack probes.

### ASI08 — Supply Chain
- **Module:** `agentic/supply_chain`
- **Technique:** pip / npm provenance + hash verification; MCP marketplace typosquat detection.
- **Real-world ref:** OX Security finding — 9 of 11 MCP registries successfully poisoned (2026).

### ASI09 — Human-Agent Trust Exploit
- **Module:** `agentic/trust_exploit`
- **Technique:** UI-spoofing markers; confirmation-fatigue patterns; misleading-summary detection.

### ASI10 — Rogue Agent
- **Module:** `agentic/rogue_agent` (ties directly to `agents/abfp`)
- **Technique:** Composite ABFP anomaly score > 70 + topic/tool outlier + identity mismatch.

## 3. MCP-specific threats

| Threat | Module | CVE / Reference |
|---|---|---|
| STDIO command-injection RCE | `protocols/mcp/audit/stdio_rce` | CVE-2025-49596 (MCP Inspector); OX Security MCP SDK class (2026) |
| Tool poisoning | `protocols/mcp/audit/tool_poisoning` | MCPTox benchmark |
| Indirect prompt injection via tool results | `agentic/goal_hijack` | CVE-2026-22785 (Orval) |
| Path traversal in filesystem MCP | `protocols/mcp/audit/path_traversal` | CVE-2025-68143, CVE-2025-68145 |
| Argument injection (git CLI) | `protocols/mcp/audit/arg_injection` | CVE-2025-68144 |
| SSRF via fetch-class tools | `protocols/mcp/audit/ssrf` | MarkItDown MCP SSRF (Microsoft, 2026) |
| DNS rebinding against localhost MCP | `protocols/mcp/audit/dns_rebind` | Endor Labs analysis (2026) |
| Configuration poisoning | `protocols/mcp/audit/config_poisoning` | OX Security (2026) |
| Microsoft MCP server RCE | `protocols/mcp/audit/microsoft` | CVE-2026-26118 |
| NGINX MCP endpoint takeover | `protocols/mcp/audit/nginx_ui` | CVE-2026-33032 |

## 4. ABFP coverage of agent-layer STRIDE

| STRIDE | ABFP Signal |
|---|---|
| Spoofing | Fingerprint mismatch on known agent identity |
| Tampering | Payload-entropy / schema drift from baseline |
| Repudiation | Missing expected publish cadence (silent agent) |
| Information Disclosure | New subscription to sensitive topics |
| Denial of Service | Anomalous burst / inter-publish-interval collapse |
| Elevation of Privilege | Publish to topic outside learned profile |

## 5. Out of scope

- Direct LLM model attacks (jailbreaks, adversarial inputs against weights).
- Training-time data poisoning.
- Physical / hardware attacks on robotic platforms.

## References

- OWASP Top 10 for Agentic Applications 2026 — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- OX Security: "The Mother of All AI Supply Chains" (2026)
- Trend Micro: "Update on Exposed MCP Servers" (2026)
- Vulnerable MCP Project — https://vulnerablemcp.info/
