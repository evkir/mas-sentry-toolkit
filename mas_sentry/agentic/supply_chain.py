# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASI04 — Agentic Supply Chain Compromise.

Audits:
- Pinned vs floating versions in requirements/package.json
- Direct git+ dependencies (unauthenticated source code pulls)
- Typosquat-style MCP server names from the marketplace (Levenshtein-1
  to a small allowlist of well-known names)
- Missing hash pinning for pip / lockfile for npm
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mas_sentry.advisories import AdvisorySource, NullSource, PinVerdict, SourceState, verdict
from mas_sentry.advisories.pins import PinSet, read_pins
from mas_sentry.core.gating import parse_severity

from .base import AgenticFinding, AsiCategory

# What an advisory finding is worth when the advisory itself states no rating.
# PYSEC records frequently carry none, so this is the common case rather than
# the edge. The band is ours, not the advisory's, and the finding says so.
#
# MEDIUM rather than something lower because the uncertainty is in the severity,
# never in the match: the pin is a release a published advisory names. Under-
# rating it would slip a real flaw under a threshold, which is the direction
# R-2.1 treats as the expensive one. MEDIUM clears a --fail-on low gate and not
# a --fail-on high one, so a strict pipeline is not reddened by an unrated
# record while a thorough one still stops.
_UNRATED_SEVERITY = "MEDIUM"

# Past this, the feed is reported as stale. Tied to how often this project
# re-audits rather than chosen for roundness: supply-chain.yml runs weekly, so a
# feed older than a week means a run was answered from data that predates the
# previous run's window, which is where staleness starts hiding findings between
# two of our own audits.
_DEFAULT_MAX_AGE_DAYS = 7

# Subset of well-known MCP server names commonly typosquatted.
_KNOWN_MCP_NAMES = {
    "mcp-server-git",
    "mcp-server-filesystem",
    "mcp-server-github",
    "mcp-server-postgres",
    "mcp-server-sqlite",
    "mcp-server-fetch",
    "mcp-server-puppeteer",
    "mcp-server-time",
    "mcp-server-memory",
}

# npm version specifiers that admit transparent supply-chain shifts.
_NPM_FLOATING_PREFIXES = ("^", "~", ">", "<")
_NPM_FLOATING_LITERALS = {"*", "latest", ""}


@dataclass(slots=True)
class SupplyChainContext:
    requirements_path: Path | None = None
    package_json_path: Path | None = None
    installed_mcp_names: list[str] | None = None

    # Defaults to a source that holds nothing rather than to None. An optional
    # source grows a branch that skips the check, and a skipped check reports no
    # findings - which in a report is indistinguishable from a check that ran
    # and found nothing (R-2.1). NullSource answers "unavailable", which is a
    # result the report can carry.
    advisories: AdvisorySource = field(default_factory=NullSource)
    max_advisory_age_days: int = _DEFAULT_MAX_AGE_DAYS

    # The scan's reference time, injected so a verdict about stale data is the
    # same in a test, in CI and on a workstation (R-7.2). Resolved at audit time
    # when left unset.
    now: datetime | None = None


def audit_supply_chain(ctx: SupplyChainContext, target: str) -> list[AgenticFinding]:
    findings: list[AgenticFinding] = []
    if ctx.requirements_path and ctx.requirements_path.exists():
        findings.extend(_audit_requirements(ctx.requirements_path, target))
        findings.extend(_audit_pinned_advisories(ctx, target))
    if ctx.package_json_path and ctx.package_json_path.exists():
        findings.extend(_audit_package_json(ctx.package_json_path, target))
    if ctx.installed_mcp_names:
        findings.extend(_audit_mcp_names(ctx.installed_mcp_names, target))
    return findings


def _audit_requirements(path: Path, target: str) -> list[AgenticFinding]:
    specs = _extract_specs(path)
    out: list[AgenticFinding] = []
    floating = 0
    git_direct = 0
    total = 0
    for spec in specs:
        total += 1
        if spec.startswith(("git+", "-e ")) or "git+" in spec:
            git_direct += 1
        elif not re.search(r"==\d", spec) and "--hash" not in spec:
            floating += 1
    if floating > 0:
        out.append(
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="MEDIUM",
                title=f"{floating}/{total} requirements without exact version pin",
                detail="Floating versions admit transitive supply-chain attacks",
                target=target,
                evidence={
                    "file": str(path),
                    "floating": floating,
                    "total": total,
                },
                cwe="CWE-1357",
            )
        )
    if git_direct > 0:
        out.append(
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="HIGH",
                title=f"{git_direct} direct git/editable installs in requirements",
                detail=("Unauthenticated git pulls bypass PyPI metadata + hash checks"),
                target=target,
                evidence={"file": str(path), "git_direct": git_direct},
                cwe="CWE-829",
            )
        )
    return out


def _audit_pinned_advisories(ctx: SupplyChainContext, target: str) -> list[AgenticFinding]:
    """Weigh every exact pin against a locally held advisory feed.

    Nothing here reaches the network. The feed is whatever the operator fetched
    deliberately, and a per-package query would ship the target's dependency
    list off the host, which R-7.3 forbids.

    The unavailable case is reported rather than skipped. A scan that silently
    omits this check produces the same empty result as one that ran it and found
    nothing clean - the pair R-2.1 exists to keep apart - so an unconfigured
    feed is a finding of its own.
    """
    assert ctx.requirements_path is not None
    state = ctx.advisories.state()
    if not state.available:
        return [
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="INFO",
                title="Pins were not checked against any advisory feed",
                detail=(
                    "No release was weighed against a published advisory, so a clean supply-chain "
                    f"result here does not mean the pins are clean: {state.reason}"
                ),
                target=target,
                evidence={"file": str(ctx.requirements_path), "reason": state.reason},
            )
        ]

    pins = read_pins(ctx.requirements_path)
    now = ctx.now or datetime.now(UTC)
    out: list[AgenticFinding] = []
    unknown: list[str] = []

    for pin in pins.pins:
        for advisory in ctx.advisories.advisories_for(pin.name):
            result = verdict(advisory, pin.version)
            if result.applies is True:
                out.append(_advisory_finding(ctx, target, pin.name, pin.version, result, state, now))
            elif result.applies is None:
                unknown.append(f"{advisory.id} against {pin.name} {pin.version}: {result.basis}")

    out.extend(_coverage_findings(ctx, target, pins, unknown, state, now))
    return out


def _advisory_finding(
    ctx: SupplyChainContext,
    target: str,
    name: str,
    version: str,
    result: PinVerdict,
    state: SourceState,
    now: datetime,
) -> AgenticFinding:
    """One pinned release a published advisory names as affected."""
    advisory = result.advisory
    basis = result.basis
    severity, rated = _severity_of(advisory.severity)
    detail = advisory.summary
    if not rated:
        detail = (
            f"{detail} The advisory states no severity, so this {severity} band is the scanner's "
            "floor for an unrated advisory rather than the advisory's own rating."
        )
    return AgenticFinding(
        asi=AsiCategory.SUPPLY_CHAIN,
        severity=severity,
        title=f"{name} {version} is affected by {advisory.id}",
        detail=detail,
        target=target,
        evidence={
            "file": str(ctx.requirements_path),
            "package": name,
            "pinned": version,
            "advisory": advisory.id,
            "aliases": list(advisory.aliases),
            "basis": basis,
            "severity_stated_by_advisory": rated,
            "advisory_db_exported_at": _isoformat(state.exported_at),
            "advisory_db_age_days": state.age_days(now),
        },
        cwe="CWE-1395",
        references=advisory.references,
    )


def _coverage_findings(
    ctx: SupplyChainContext,
    target: str,
    pins: PinSet,
    unknown: list[str],
    state: SourceState,
    now: datetime,
) -> list[AgenticFinding]:
    """Say what the advisory pass could not speak for, and how old its data was.

    Three separate findings rather than one. They are acted on differently: a
    stale feed is fixed by an update, an unreadable requirement line by editing
    the file, and an incomparable advisory by reading it. Merging them would
    produce a row nobody can act on.
    """
    out: list[AgenticFinding] = []
    age = state.age_days(now)
    exported = _isoformat(state.exported_at)
    base = {
        "file": str(ctx.requirements_path),
        "advisory_db_exported_at": exported,
        "advisory_db_age_days": age,
    }

    if age is not None and age > ctx.max_advisory_age_days:
        out.append(
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="INFO",
                title=f"Advisory data is {age} days old",
                detail=(
                    f"The findings above were weighed against a feed exported on {exported}, which is "
                    f"older than the {ctx.max_advisory_age_days}-day threshold. They stand; an advisory "
                    "published since that export would not appear among them."
                ),
                target=target,
                evidence={**base, "max_age_days": ctx.max_advisory_age_days},
            )
        )

    if pins.unpinned:
        out.append(
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="INFO",
                title=f"{len(pins.unpinned)} requirement line(s) name no release to check",
                detail=(
                    "An advisory is weighed against one release, so these lines were not checked "
                    "against the feed. The pinning of the file itself is judged separately."
                ),
                target=target,
                evidence={
                    **base,
                    "checked": len(pins.pins),
                    "unchecked": [{"line": u.raw, "reason": u.reason} for u in pins.unpinned],
                },
            )
        )

    if unknown:
        out.append(
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="INFO",
                title=f"{len(unknown)} advisory/pin pair(s) could not be compared",
                detail=(
                    "These advisories name the pinned package but could not be weighed against its "
                    "version. They are neither a hit nor a clean result and want reading by hand."
                ),
                target=target,
                evidence={**base, "pairs": unknown},
            )
        )

    return out


def _severity_of(stated: str | None) -> tuple[str, bool]:
    """Resolve an advisory's own rating, and say whether it had one.

    An unreadable rating is treated as no rating rather than as an error. The
    band would otherwise come from a string nobody validated, and a severity the
    evidence does not support is the verdict R-7.2 rules out.
    """
    if stated is None:
        return _UNRATED_SEVERITY, False
    try:
        return parse_severity(stated).value, True
    except ValueError:
        return _UNRATED_SEVERITY, False


def _isoformat(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


# A requirements.txt line is a real spec only if it begins with a PEP 508 name
# token or a direct git/editable ref. This rejects TOML scaffolding, option
# lines (-r/-c/--index-url), and --hash continuations that would otherwise be
# miscounted as dependencies.
_REQ_LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]+\])?\s*([<>=!~@;].*)?$")


def _is_pyproject(path: Path) -> bool:
    if path.name == "pyproject.toml":
        return True
    if path.suffix != ".toml":
        return False
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return "project" in data or "build-system" in data


def _specs_from_pyproject(path: Path) -> list[str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    project = data.get("project", {})
    specs: list[str] = list(project.get("dependencies", []) or [])
    for group in (project.get("optional-dependencies", {}) or {}).values():
        specs.extend(group or [])
    return [s for s in specs if isinstance(s, str)]


def _specs_from_requirements(path: Path) -> list[str]:
    out: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("git+", "-e ")):
            out.append(line)
            continue
        if line.startswith("-"):  # -r, -c, --index-url, --hash continuations
            continue
        if " = " in line or line.startswith(("[", '"', "'")):  # TOML scaffolding
            continue
        if _REQ_LINE.match(line):
            out.append(line)
    return out


def _extract_specs(path: Path) -> list[str]:
    if _is_pyproject(path):
        return _specs_from_pyproject(path)
    return _specs_from_requirements(path)


def _is_floating_npm_version(v: str) -> bool:
    if v in _NPM_FLOATING_LITERALS:
        return True
    return v.startswith(_NPM_FLOATING_PREFIXES)


def _audit_package_json(path: Path, target: str) -> list[AgenticFinding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[AgenticFinding] = []
    deps = {
        **(data.get("dependencies") or {}),
        **(data.get("devDependencies") or {}),
    }
    floating = sum(1 for v in deps.values() if isinstance(v, str) and _is_floating_npm_version(v))
    if floating > 0:
        out.append(
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="MEDIUM",
                title=f"{floating}/{len(deps)} npm deps use floating versions",
                detail=(
                    "Ranges (^/~/>/<), wildcards (*), and 'latest' admit malicious patch versions without re-review"
                ),
                target=target,
                evidence={
                    "file": str(path),
                    "floating": floating,
                    "total": len(deps),
                },
            )
        )
    has_lock = (
        (path.parent / "package-lock.json").exists()
        or (path.parent / "pnpm-lock.yaml").exists()
        or (path.parent / "yarn.lock").exists()
    )
    if not has_lock:
        out.append(
            AgenticFinding(
                asi=AsiCategory.SUPPLY_CHAIN,
                severity="HIGH",
                title="No lockfile present alongside package.json",
                detail=("Without a lockfile, builds are non-deterministic and vulnerable to dep-confusion"),
                target=target,
                evidence={"dir": str(path.parent)},
                cwe="CWE-1357",
            )
        )
    return out


def _audit_mcp_names(names: list[str], target: str) -> list[AgenticFinding]:
    out: list[AgenticFinding] = []
    for n in names:
        if n in _KNOWN_MCP_NAMES:
            continue
        for known in _KNOWN_MCP_NAMES:
            if _levenshtein(n, known) == 1:
                out.append(
                    AgenticFinding(
                        asi=AsiCategory.SUPPLY_CHAIN,
                        severity="CRITICAL",
                        title=f"Possible MCP-server typosquat: '{n}' vs '{known}'",
                        detail=("Single-character difference from a well-known server name — verify provenance"),
                        target=target,
                        evidence={"installed": n, "known": known},
                        cwe="CWE-829",
                    )
                )
                break
    return out


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
