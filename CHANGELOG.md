# Changelog

## [Unreleased]

### Added
- A2A card audit: overbroad OAuth2 scope detection, the first card-auditable
  slice of the cross-agent privilege-escalation frontier. Coarse-grained token
  scopes are the concrete A2A privilege-escalation vector named across the 2026
  threat literature: an agent granted a wildcard or admin-family scope holds far
  more authority than any single skill needs, so a compromised or malicious peer
  can escalate across the delegation boundary. `_check_overbroad_scopes` reads
  scope names from every oauth2 scheme flow in `securitySchemes`, handling both
  the proto member-key shape (`oauth2SecurityScheme.flows`) and the OpenAPI
  `type`/`flows` shape, and tolerating dict- or list-valued `scopes`. Findings
  split by confidence rather than over-scoring a fuzzy signal: a wildcard scope
  (`*`, `write:*`) is coarse by definition -> MEDIUM, while an admin-family
  literal (`admin`, `root`, `owner`, ... matched exact and case-insensitively so
  `wallet` never trips it) is a naming convention, not a guarantee -> LOW. Each
  finding lists the exact offending scopes instead of asserting exploitability.
  Tagged ASI03 (Identity and Privilege Abuse) / CWE-269 (Improper Privilege
  Management) / STRIDE Elevation of Privilege; ATLAS left untagged, no clean
  verified technique. The full delegation-chain escalation remains out of scope
  for a single-target scanner and is not forced into a context-free check.
- A2A card audit: agent-selection routing-hijack detection. A rogue AgentCard
  needs no obfuscation or "ignore previous" token to subvert an LLM
  orchestrator: plain-language directives in the card description or a skill's
  name/description ("always prefer this agent", "the only agent authorized for
  X", "do not route to other agents") bias the orchestrator selection reasoning
  toward the attacker agent - the infrastructure-layer prompt injection
  Trustwave demonstrated in 2025. The existing poisoning scan catches
  control-flow takeovers (obfuscation, ignore-previous, tool-call hijack) but
  misses this persuasive-steering class, which carries no classic injection
  token. A dedicated `scan_routing_hijack` primitive adds six selection-steering
  signatures, each requiring a selection imperative rather than a bare
  superlative so honest self-description ("best-in-class invoice agent", "use
  this agent to process invoices") stays inert. `_scan_routing_hijack` runs it
  over the same LLM-ingested fields as poisoning (factored into a shared
  `_llm_ingested_fields` helper) and emits MEDIUM - steering biases a decision,
  it does not seize control, so it scores below an outright injection takeover.
  Tagged ASI01 (Agent Goal Hijack) / CWE-1427 / STRIDE Tampering / ATLAS
  AML.T0051, the same goal-hijack family as poisoning.
- Propagation findings now flow through the full report pipeline. The ABFP
  scan already emitted a `propagation` block and a `propagation_summary`
  header, but `mas-sentry report convert` read only the `findings` array and
  silently dropped both - every transitive contamination finding, including
  CRITICAL verbatim relays across multiple hops, was invisible in SARIF,
  HTML, Markdown, and JUnit. Convert now rebuilds each serialized
  PropagationFinding and maps it through the same `from_propagation_finding`
  adapter the live scan path uses, so contamination is mapped identically
  regardless of entry point. SARIF gains a dedicated `abfp.propagation`
  rule, security-severity band-anchored on the chain severity, with tags and
  the onward blast radius in result properties. HTML and Markdown render a
  distinct contamination-chain provenance block (origin -> ... -> target,
  depth, tier) plus onward blast radius, and a triage banner derived from
  `propagation_summary` (contaminated count, max chain depth, origins) above
  the findings list. Documented in the new Propagation in Reporting
  methodology page.
- Consume-edge inference reviving cascade blast-radius in live passive
  scans. A passive MAS listener observes PUBLISH traffic but no SUBSCRIBE
  packets, so the topic graph's subscribe edges stayed empty and
  `blast_radius` computed an empty downstream reach - the cascade was dead
  code in the exact scenario it targets. MAS-Sentry now infers consume edges
  from the same injection re-emission evidence used for transitive
  propagation: when a downstream agent re-emits a directive first seen from
  an upstream source, it must have consumed the topic that source emitted on,
  and nearest-source attribution pins that topic. Inferred edges enter the
  topic graph under a distinct `subscribe-inferred` kind and never overwrite
  an observed subscribe, so a behavioral inference is never mistaken for
  ground truth. `blast_radius` splits its reach into observed `direct` /
  `transitive` and `inferred_direct` / `inferred_transitive`, crediting an
  agent reachable both ways as observed. The passive scan loop is now
  exercised end-to-end against a mocked broker. Documented in the new
  Consume-Edge Inference methodology page.
- Transitive indirect-prompt-injection propagation detection in the ABFP
  scan. Beyond flagging agents that emit injection directives, MAS-Sentry now
  reconstructs how a directive spreads across agents from observed re-emission,
  modeling the cross-agent infection that per-agent guardrails and topology-
  only blast-radius both miss. Two evidence tiers are used: verbatim (a
  distinct agent forwards an identical poisoned payload, hash-anchored) and
  directive (a distinct agent re-emits the same STRONG pattern). Each hop is
  attributed to its nearest prior source, yielding infection chains; the graph
  is kept acyclic so propagation depth is well defined. Injection events are
  captured bounded (patterns + payload hash only, never the payload). Chain
  severity is computed directly - a single directive hop is HIGH, a verbatim
  relay or a directive surviving two or more hops is CRITICAL - rather than
  through the weighted-mean anomaly score that would dilute a chain-level
  signal. The scan report gains a `propagation` block (per contaminated agent:
  origin, chain, depth, tier, severity, taxonomy, and fused onward blast
  radius) plus a `propagation_summary` triage header. Findings are tagged
  ASI01 / ASI05 Cascading Failure / CWE-1427 / STRIDE Tampering / AML.T0051.
  Documented in the new Transitive Injection Propagation methodology page.
- Live `mas-sentry a2a scan` command activating the full Agent-to-Agent
  vertical, previously a dormant library. The scan discovers an endpoint's
  AgentCard, audits it passively, and - with `--active` - runs live probes
  (task-id collision, unauthorized cancel, indirect-injection canary),
  mapping every result through the A2A adapters into unified Findings. Output
  is written to `reports/a2a.json` and flows straight into `mas-sentry report
  convert` (HTML / Markdown / SARIF / JUnit) with no re-adaptation. Scope is
  enforced centrally by the A2A client, so non-lab targets require
  `--confirm-scope` even for the passive card fetch; `--active` governs
  intrusiveness and prints an authorized-use notice. Probe outcomes carry
  taxonomy only when a probe fails (task-id collision ASI03 / CWE-345, cancel
  CWE-862, indirect-injection ASI01 / CWE-1427 / AML.T0051); a probe that
  holds is recorded INFO. The structural AgentCard findings (missing or
  anonymous auth, uncapped streaming, unsigned push callbacks, excessive skill
  surface) now also carry the four-lens taxonomy, so every A2A finding - not
  only poisoning and insecure transport - is ranked by SARIF security-severity
  and visible to cross-taxonomy filters. Documented in the new A2A Scanning
  methodology page.
- Agent Card Poisoning detection for the A2A card audit. The audit now scans
  the AgentCard description and every skill's name/description with the shared
  injection primitive (`mas_sentry.core.injection_scan`), flagging directives
  that hijack an orchestrator's LLM-based task-routing reasoning - the same
  detector now covers three surfaces: MCP tool descriptors, live agent traffic,
  and A2A cards. Poisoning findings carry the four-lens taxonomy (ASI01 Goal
  Hijack, CWE-1427, STRIDE Tampering, MITRE ATLAS AML.T0051). A cleartext
  (`http://`) card endpoint is now flagged (CWE-319, STRIDE Tampering) as it
  invites card tampering in transit. A2A card findings propagate their
  per-finding taxonomy into the unified Finding tags.
- Passive indirect-prompt-injection (IPI) detection over live agent traffic.
  Every MQTT payload observed during an ABFP scan is scanned in-flight for
  injection directives (obfuscation via zero-width / Unicode-tag characters,
  `ignore previous instructions`, system-role overrides, new-task directives,
  tool-call hijacks). An agent that publishes such directives into the topic
  graph - because it was poisoned upstream or is malicious - surfaces as a new
  `injection` scoring dimension, and the existing cascade blast-radius then
  quantifies the downstream contamination reach over the same graph. This
  catches IPI travelling agent-to-agent, a class that input/output guardrails
  on a single agent miss. Payloads are scanned but not retained, so the
  message buffer keeps its size+hash-only memory discipline. The `injection`
  dimension carries the full four-lens taxonomy: ASI01 Goal Hijack, CWE-1427
  (Improper Neutralization of Input Used for LLM Prompting), STRIDE Tampering,
  and MITRE ATLAS AML.T0051 (LLM Prompt Injection), rendering as HTML badges
  and flowing into SARIF.
- Four-lens taxonomy tags for the MCP `tool_poisoning` check (ASI01 Goal
  Hijack, CWE-1427, STRIDE Tampering, MITRE ATLAS AML.T0051), closing the
  gap where MCP tool-poisoning findings - which carry IPI directives embedded
  in tool-descriptor fields - previously shipped without an ATLAS technique
  or CWE. The `arg_injection` check now carries command-injection tags
  (ASI02 Tool Misuse, CWE-77, STRIDE Tampering); it is deliberately left
  ATLAS-untagged as no verified technique cleanly matches.
- A2A card audit: signed-card absence detection. `audit_agent_card` now
  flags an AgentCard published without a JWS signature (A2A v1.0
  AgentCardSignature, RFC 7515 over RFC 8785-canonicalized content) - an
  unsigned card cannot be distinguished from a spoofed or on-path-modified
  one. Tagged ASI03 Identity Abuse, CWE-347, STRIDE Spoofing.
- A2A card audit: bare-API-key-only scheme detection. Flags a v1.0 card
  whose only declared `securitySchemes` entry is a static API key with no
  oauth2/http/openIdConnect/mtls alternative offered - a key alone has no
  built-in rotation or expiry and is the weakest of the five v1.0 scheme
  types. LOW, tagged ASI03 Identity Abuse, CWE-798, STRIDE Spoofing. Scheme
  type is resolved from either the v1.0 spec's member-based discriminator
  (`apiKeySecurityScheme`, `oauth2SecurityScheme`, ...) or the OpenAPI-style
  `type` field seen in real vendor examples, since the two sources disagree
  on the canonical wire shape.

### Fixed
- A2A card discovery only ever requested the legacy `/.well-known/agent.json`
  URI (A2A v0.3.x). A2A v1.0 (stable since April 2026, Linux Foundation)
  moved discovery to `/.well-known/agent-card.json` - against a real v1.0
  target, `A2AClient.discover()` 404'd outright and the scan never started.
  Discovery now tries the v1.0 URI first and falls back to the legacy one on
  a plain 404, so both generations of a mixed real-world fleet are reachable.
- `card_audit`'s no-auth / scheme-`'none'` checks read only the legacy
  `authentication.schemes` field, which A2A v1.0 does not populate at all
  (v1.0 declares auth via `securitySchemes` + `securityRequirements`
  instead). Every real v1.0 card with authentication correctly configured
  was unconditionally HIGH-flagged "no authentication schemes" regardless of
  actual auth. `audit_agent_card` now branches on which shape the raw card
  carries: v1.0 cards are judged by `securityRequirements[]` actually
  enforcing a declared `securitySchemes` entry; legacy v0.3.x cards keep the
  original schemes-list check.
- A2A active probing spoke an invented wire format that matched no real A2A
  binding: bare POST bodies to `/tasks/send` `/tasks/get` `/tasks/cancel`,
  not the JSON-RPC 2.0 envelope (`jsonrpc`/`id`/`method`/`params`) the
  protocol's most common binding requires. Every active probe (task-id
  collision, unauthorized-cancel, indirect-injection) had therefore only
  ever exchanged valid traffic with this suite's own mocks, never a real
  agent. The client now wraps every call in a correct JSON-RPC envelope with
  the correct method names (`message/send`, `tasks/get`, `tasks/cancel`) and
  a v1.0-shaped outgoing message (`ROLE_USER`, member-based `Part`). A new
  `A2ARpcError` surfaces JSON-RPC-level rejections (HTTP 200 with an `error`
  body, how a compliant server signals TaskNotFound / TaskNotCancelable) as a
  distinct exception from transport failures; the unauthorized-cancel probe
  and the scan runner both treat it as a safe rejection rather than silently
  misparsing it as an empty task.
- A2A task-state parsing only recognized v0.3.x kebab-case values; v1.0
  renamed every value to `TASK_STATE_`-prefixed SCREAMING_SNAKE_CASE, so
  every real v1.0 task response fell through to the `UNKNOWN` fallback and
  terminal-state detection never fired - polling ran to its timeout instead
  of stopping when a task finished. `TaskState` now normalizes both shapes,
  and the previously-missing `REJECTED` and `AUTH_REQUIRED` states (real in
  both generations) were added, with `REJECTED` now correctly treated as
  terminal.

### Added
- A2A client resolves the JSON-RPC endpoint from the discovered AgentCard's
  declared interfaces rather than always POSTing to `base_url`. v1.0 cards
  list every binding+URL combination in `supportedInterfaces[]` (order is
  preference, not binding); v0.3.x cards use `url` +
  `preferredTransport`/`additionalInterfaces[]`. `_resolve_jsonrpc_endpoint`
  scans for a JSON-RPC-bound entry in either shape. A new
  `A2AUnsupportedBindingError` is raised only when a card explicitly declares
  interfaces and none is JSON-RPC - an actionable "cannot actively probe this
  target" signal; a card with no interface information at all still falls
  back to `base_url`. The scan runner skips probing (keeping card-audit
  findings) rather than aborting when a target offers no JSON-RPC binding.

### Changed
- The IPI pattern scanner (`scan_string` / `InjectionMatch`) moved to
  `mas_sentry.core.injection_scan` as a shared primitive consumed by both the
  MCP tool-descriptor audit and the ABFP live-traffic detector, removing a
  would-be `agents -> protocols.mcp` layering dependency. The MCP audit API is
  unchanged (re-exported).

## [0.5.0] - 2026-07-01 - Four taxonomy lenses, MCP tool-drift, cascade blast-radius, SARIF security-severity

### Added
- SARIF rules now carry a GitHub `security-severity` score, so findings
  rank in the GitHub code-scanning Security tab instead of appearing
  unranked. The number is anchored on the finding's textual severity band
  (CRITICAL >=9.0, HIGH 7.0-8.9, MEDIUM 4.0-6.9, LOW <=3.9) and, for
  scored rogue-agent findings, positioned within that band by the real
  composite anomaly score, so a higher-scoring rogue outranks a lower one.
  Non-scored MCP checks take the band midpoint; a rule ranks at its worst
  finding.
- MITRE ATLAS technique tags as a fourth taxonomy lens (alongside
  ASI/CWE/STRIDE) on findings with a clean, verified match: MCP tool
  rug-pull and shadowing -> AML.T0110 (AI Agent Tool Poisoning); agentic
  goal hijack -> AML.T0051 (LLM Prompt Injection), memory poisoning ->
  AML.T0080 (AI Agent Context Poisoning), supply chain -> AML.T0048 (ML
  Supply Chain Compromise). Tags render as dedicated HTML badges and flow
  into SARIF, giving findings the AI-native ATT&CK vocabulary that SOC and
  audit workflows increasingly expect. Detectors without a defensible
  technique match are deliberately left untagged.
- Cascade blast-radius analysis for rogue-agent findings. Using the live
  agent-topic interaction graph, each rogue finding now reports how far a
  contamination it injects could spread: the topics it publishes into, the
  direct subscribers one hop away, and the full transitive set of
  downstream agents it could reach. Surfaced in `evidence.blast_radius`
  across the JSON, HTML (a per-finding cascade view), and SARIF
  (`properties.blast_radius`) outputs, turning the descriptive graph into a
  predictive contamination-reach signal.
- MCP tool-descriptor drift detection (`mcp scan --tool-baseline <path>`).
  The first run captures a per-tool descriptor digest baseline; later runs
  flag `tool_rug_pull` when a tool's description or input schema mutates
  after approval (the post-approval rug pull most MCP clients miss),
  `tool_shadowing` when two tools share a name in one enumeration, and
  tool_added/tool_removed deltas. Security-meaningful drift carries
  ASI/CWE/STRIDE tags (rug pull -> ASI08 Supply Chain / CWE-494 /
  Tampering; shadowing -> ASI02 Tool Misuse / CWE-290 / Spoofing) across
  the JSON, HTML, and SARIF surfaces.
- ABFP findings now carry STRIDE taxonomy tags alongside the existing
  ASI/CWE tags, derived from the dimensions that fired (identity ->
  Spoofing, topic -> Elevation of Privilege, payload/burst/timing ->
  Denial of Service). Tags render as dedicated HTML badges and flow into
  SARIF result tags, giving rogue-agent findings a three-lens
  (ASI/CWE/STRIDE) classification on the same fired signals.

### Removed
- Orphaned `agents/interaction_graph.py` (and its test), superseded by the
  live `abfp/topic_graph` builder and unreachable from any product path.
- Dead `abfp_stride_mapper` module and its false-contract test. The mapper
  keyed off a `type` field the ABFP engine never emits, so it was unreachable
  in production while its unit test inflated coverage. The dimension-driven
  STRIDE tagging above supersedes it.
- Removed the orphaned legacy threat-modeling and reporting pipeline:
  the `threat_modeling` STRIDE subsystem (catalog, mappers, aggregator,
  attack trees, CVSS calculator, ROS2 threats), the `MASAuditReport`
  reporting stack (`report_model`, `HTMLReportGenerator`, markdown
  report), and the superseded `AnomalyDetector`. ~440 statements with no
  product consumers, kept green only by their own unit tests. The live
  path (`abfp.scoring` + `report convert` -> unified HTML/SARIF/JSON/
  JUnit/Markdown over `core.finding`) is the single supported pipeline.

## [0.4.0] - 2026-06-22 - Full dimension parity across surfaces + burst-cadence detection

### Added
- ABFP rogue-scan findings now render in HTML reports: the `report convert`
  bridge adapts ABFP-shaped findings (agent id, diff, dimensions) to the
  canonical finding model, so they no longer produce blank cards.
- Per-finding `Drivers` section in the HTML report listing each scoring
  dimension (name, raw value, reason).
- ABFP graph-centrality table in the HTML report (pub/sub degree, distinct
  topics, betweenness, eigenvector) when a scan emits a graph block.
- Burst-cadence dimension in impersonation/rogue scoring: flags an agent that
  develops bursty traffic or loses its periodic cadence relative to the
  baseline (weight 0.15), surfaced through the existing Drivers output.
- ABFP scoring drivers now flow into SARIF: a compact driver summary in the
  result message plus structured `drivers`, `agent_id`, and `score` under
  result properties, so CI code-scanning shows why an agent was flagged.
- ABFP findings are enriched with ASI/CWE taxonomy tags derived from the
  dimensions that fired (e.g. identity -> CWE-290, burst -> CWE-400),
  rendered as HTML badges and SARIF result tags.

## [0.3.0] - 2026-06-22 - Behavioral baselines + reconnected ABFP detectors

### Added
- ABFP per-agent graph-centrality metrics (`graph_metrics`) wired into the scan
  report and a CLI table (pub/sub degree, distinct topics, betweenness,
  eigenvector).
- `ScanSnapshot` behavioral baseline (topic graph + per-agent timing/payload
  digest), persisted each scan via `--snapshot`.
- Cross-run comparison via `--baseline`: a prior snapshot revives rogue-agent
  drift detection (previously a no-op on first run) and feeds the impersonation
  detector.
- Impersonation detector restored as digest-native dimensions (timing, payload,
  identity) that fold into the rogue score via `detect_rogue`'s
  `extra_dimensions` hook, surfacing agents whose fingerprint diverges even
  without a topology change.
- Finding `dimensions` emitted in the JSON report and a `Drivers` column in the
  CLI showing which signals drove each score.
- Authorized-use reminder on active scans (stderr) plus liability-waiver and
  heuristic-findings disclaimers (no-warranty, false-positive/negative caveat)
  in the README.

### Fixed
- Rogue topic dimension no longer emits a spurious signal for agents with no new
  topics.

## [0.2.1] - 2026-06-20 - First PyPI release

### Added
- `release.yml`: isolated `publish-pypi` job using OIDC trusted publishing
  (`pypa/gh-action-pypi-publish`), tag-only, no API tokens. The package is
  now installable from PyPI.

### Notes
- No runtime code changes from 0.2.0; this release exists to ship the PyPI
  distribution path via the tag-triggered pipeline.

## [0.2.0] — 2026-06-19 — Pivot to Agentic MAS Security

### Changed
- Relicensed from MIT to **AGPL-3.0-or-later** (sole contributor consent).
- Repositioned: MQTT/AMQP-only → unified MQTT/AMQP **+ MCP + A2A + agentic** toolkit.
- All findings now map to OWASP Agentic Top 10 (2026) in addition to STRIDE.
- Python floor raised to 3.11.
- CI badge URL fixed (user70616E6461 → evkir).
- pyproject.toml migrated to hatchling backend.

### Added
- THREAT_MODEL.md (ASI01-ASI10, MCP CVEs, ABFP-STRIDE table).
- CI matrix Python 3.11/3.12/3.13/3.14.
- scripts/add_spdx_header.sh (idempotent, shebang-aware).
- Pre-commit hooks (ruff/format) and Renovate dependency automation.
- Integration tests against a live Mosquitto broker via docker compose.
- Supply-chain security: hash-pinned `requirements-lock.txt`, `requirements.txt`
  mirror with a drift-guard test, and `supply-chain.yml` CI (hash-verified
  install, pip-audit CVE scan, ASI08 dogfood self-audit, dependency-review).
- `docs/SUPPLY-CHAIN.md` documenting the pinning + verification model.
- `release.yml`: wheel + sdist build, `twine check`, and a CycloneDX SBOM
  generated from the locked deps, attached to the GitHub Release on tag.
- CLI `--version` (via importlib.metadata) and documented shell completion.
- `project.urls` Security + Threat Model entries for PyPI sidebar discovery.
- Five verified usage example workflows under `docs/examples/`.
- Dogfood ASI08 self-audit (`reports/SELF-AUDIT.md`) - 0 findings on the
  hash-pinned lockfile.

### Changed (hardening)
- mypy is now a hard CI gate (previously advisory / continue-on-error).
- ASI08 supply-chain scanner is pyproject-aware and ignores non-requirement
  lines (option flags, `--hash` continuations, TOML scaffolding).
- pytest config consolidated into `pyproject.toml` (asyncio auto,
  strict-markers, coverage gate 60%); removed the shadowing `pytest.ini`.
- Rewrote `ARCHITECTURE.md` and `docs/api/README.md` to the current
  `UnifiedThreatEngine` module model; the old docs described the deleted
  `SentryEngine` and shipped copy-paste examples that would ImportError.

### Fixed
- ASI08 parser miscounted TOML and option lines as dependencies, producing a
  false "N/N unpinned" finding when pointed at a `pyproject.toml`.
- ABFP report serialization of slotted `BaselineStatus` via `asdict`.
- SARIF emitter no longer hardcodes the tool version; it is derived from
  package metadata (importlib.metadata), so emitted reports never drift.

### Removed (pre-release dead-code audit)
- Pre-pivot `SentryEngine 1.0` MQTT/AMQP cluster: `core/engine.py`,
  `core/session.py`, `core/config.py`, `core/display.py`, `core/exporter.py`,
  `core/multi_target.py`, `protocols/auto_detect.py`, `agents/profiles.py` --
  all superseded by `UnifiedThreatEngine` and the `reporting/` package.
- Unwired SQLAlchemy persistence (`agents/abfp/storage.py`) and its
  `sqlalchemy` + `alembic` runtime dependencies (alembic was a phantom dep:
  no migrations, no alembic.ini).
- Duplicate / unsafe ABFP fragments: `agents/abfp/stride_map.py` (duplicated
  the live `abfp_stride_mapper`) and `reporting/abfp_html.py` (duplicated
  `unified_html` without jinja2 autoescape).
- Unwired ABFP features `agents/abfp/impersonation.py` and
  `agents/abfp/graph_metrics.py`, deferred to v0.3.0 as properly wired+tested
  modules (code preserved in git history).
- Second divergent click CLI in `__main__.py` (sniff/abfp/fingerprint/walk/
  audit/probe/learn/config) frozen at a hardcoded v0.1.0 banner and the
  pre-pivot MQTT/AMQP command set; `python -m mas_sentry` now delegates to the
  real `mas-sentry` CLI (mas_sentry.cli:app).
- Net effect: real line coverage rose from ~66.9% to ~77% (dead 0%-modules
  out of the denominator) and the runtime dependency surface dropped by two
  direct + two transitive packages. CI coverage gate raised 60 -> 70.


All notable changes to MAS-Sentry-Toolkit are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.9.0] - 2025-05-11

### Added
- Core Engine + CLI (5 commands: scan, abfp, report, probe, graph)
- MQTT Analyzer — anonymous auth, wildcard topics, retained message poisoning
- AMQP Analyzer — vhost enumeration, credential brute-force detection
- Docker Lab — mosquitto broker + 3 MAS agents (sensor, actuator, coordinator)
- ABFP Engine Phase 1: passive behavioral fingerprinting
- ABFP Engine Phase 2: anomaly scoring (0–100)
- ABFP Engine Phase 3: drift detection and alerting
- Anomaly Detector — statistical baseline comparison
- STRIDE Threat Mapper — automated threat modeling for MAS topologies
- Report Generator — HTML, JSON, Markdown output formats
- Active Prober — authenticated and unauthenticated probe modes
- Interaction Graph — agent communication topology visualization
- HCAP Protocol Specification v0.1
- GitHub Actions CI — Python 3.10 / 3.11 / 3.12
- Type aliases and typed helpers (core/types.py)
- Coverage badge generator script

### Fixed
- numpy version pin for Python 3.13 compatibility
- pydantic version pin for Python 3.13 compatibility

### Infrastructure
- pytest-cov integration with 70% threshold
- pyproject.toml with mypy + ruff config
- SECURITY.md vulnerability disclosure policy
- ROADMAP.md with v1.0.0 milestones

---

## [0.1.0] - 2025-04-01

### Added
- Initial project scaffold
- Basic MQTT connection probe

---

## [1.0.0] - 2025-05-13

### Added
- CVSS v3.1 calculator for MAS vulnerability scoring
- IoT attack tree scenarios (AT-001, AT-002)
- ROS2/DDS threat catalog (4 scenarios)
- Threat scoring aggregation with risk level calculation
- CONTRIBUTING.md with setup and commit guide
- Full API reference docs
- Attack scenario usage examples
- STRIDE mapper tests, CVSS tests, aggregator tests

### Changed
- stride.py rewritten with threat_id, cvss_score fields
- stride_mapper.py aligned with test expectations
- numpy and pydantic version pins fixed for Python 3.13+

### Tests
- 116 commits, 100+ tests passing
- CI green on Python 3.10 / 3.11 / 3.12

---
*Released: 2026-05-15*
