# MAS-Sentry-Toolkit Roadmap

MAS-Sentry is a unified offensive-security toolkit for Multi-Agent Systems:
passive/active detection across the MQTT agent bus, the MCP protocol, and the
A2A protocol, unified under a four-lens threat taxonomy (ASI / CWE / STRIDE /
MITRE ATLAS) and a single reporting pipeline.

Current released version: **v0.5.0** (PyPI). Work accrues in the
`[Unreleased]` CHANGELOG section between releases.

---

## Shipped (through v0.5.0)

### Detection surfaces
- **ABFP** - Agent Behavioral Fingerprinting over the live MQTT bus: topic
  graph, timing cadence, payload signature, identity/impersonation, burst.
- **Rogue-agent scoring** - composite anomaly score with severity bands and
  baseline/drift comparison.
- **Cascade blast-radius** - per-finding downstream reach over the live topic
  graph (direct + transitive consumers).
- **MCP protocol audit** - fingerprint, tool poisoning, SSRF, path/arg
  traversal, DNS rebinding, STDIO RCE, and tool-drift (rug-pull / shadowing).
- **A2A card audit** - authentication, streaming/push posture, skill surface.
- **Agentic static scans** - ASI01-ASI10 detectors.

### Taxonomy and reporting
- Four-lens taxonomy tags (ASI / CWE / STRIDE / MITRE ATLAS) on findings with
  a verified match.
- Unified `Finding` model with adapters from every surface.
- Reporters: HTML (badges, drivers, cascade, centrality), Markdown, JSON,
  JUnit, and SARIF with GitHub code-scanning `security-severity` ranking.

### Supply chain and quality
- PyPI publishing via OIDC trusted publishing; wheel + sdist + CycloneDX SBOM.
- CI matrix (3.11-3.14), ruff + mypy (strict-clean, 98 source files),
  pytest with a 70% coverage floor, Codecov live coverage.
- mkdocs documentation site (mkdocs --strict clean).

---

## In progress (`[Unreleased]`)

- **Frontier IPI detection, one primitive across three surfaces.** The shared
  `core.injection_scan` primitive now backs indirect-prompt-injection detection
  in MCP tool descriptors, in live agent traffic (fused with cascade
  blast-radius for contamination reach), and in A2A agent cards (Agent Card
  Poisoning). All carry CWE-1427 / AML.T0051 taxonomy.

---

## Near-term

- **A2A `scan` command.** Wire the A2A discover -> card audit -> active probes
  path into a `mas-sentry a2a scan <url>` CLI + runtime that emits unified
  Findings through the existing report pipeline (currently library-only).
- **A2A active probes wiring** - task-id collision, unauthorized cancel, and
  goal-hijack probes surfaced as reportable findings.
- **Taxonomy depth** - expand verified ATLAS/CWE coverage as new detectors land;
  grow the shared injection pattern set (benefits all three surfaces at once).

---

## Exploratory

- **A2A protocol hardening checks** - signed AgentCard verification, mTLS /
  PKI identity posture, replay resistance.
- **Multi-agent emergent detection** - agent collusion and transitive
  contamination beyond single-hop blast-radius.
- **Protocol reach** - ROS2 / DDS collection alongside MQTT.
- **Operator surfaces** - dashboard / web UI over the unified findings model.
