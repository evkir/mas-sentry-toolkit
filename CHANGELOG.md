# Changelog

## [0.2.0-dev] — 2026-05-17 — Pivot to Agentic MAS Security

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

### Fixed
- ASI08 parser miscounted TOML and option lines as dependencies, producing a
  false "N/N unpinned" finding when pointed at a `pyproject.toml`.
- ABFP report serialization of slotted `BaselineStatus` via `asdict`.


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
