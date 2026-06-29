# Changelog

## [Unreleased]

### Added
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
