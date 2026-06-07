# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASI08 — Supply Chain.

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
from dataclasses import dataclass
from pathlib import Path

from .base import AgenticFinding, AsiCategory

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


def audit_supply_chain(ctx: SupplyChainContext, target: str) -> list[AgenticFinding]:
    findings: list[AgenticFinding] = []
    if ctx.requirements_path and ctx.requirements_path.exists():
        findings.extend(_audit_requirements(ctx.requirements_path, target))
    if ctx.package_json_path and ctx.package_json_path.exists():
        findings.extend(_audit_package_json(ctx.package_json_path, target))
    if ctx.installed_mcp_names:
        findings.extend(_audit_mcp_names(ctx.installed_mcp_names, target))
    return findings


def _audit_requirements(path: Path, target: str) -> list[AgenticFinding]:
    out: list[AgenticFinding] = []
    floating = 0
    git_direct = 0
    total = 0
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        total += 1
        if line.startswith(("git+", "-e ")):
            git_direct += 1
        elif not re.search(r"==\d", line) and not re.search(r"--hash", line):
            floating += 1
    if floating > 0:
        out.append(
            AgenticFinding(
                asi=AsiCategory.ASI08,
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
                asi=AsiCategory.ASI08,
                severity="HIGH",
                title=f"{git_direct} direct git/editable installs in requirements",
                detail=("Unauthenticated git pulls bypass PyPI metadata + hash checks"),
                target=target,
                evidence={"file": str(path), "git_direct": git_direct},
                cwe="CWE-829",
            )
        )
    return out


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
                asi=AsiCategory.ASI08,
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
                asi=AsiCategory.ASI08,
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
                        asi=AsiCategory.ASI08,
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
