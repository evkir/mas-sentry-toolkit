# SPDX-License-Identifier: AGPL-3.0-or-later
"""SARIF v2.1.0 emitter — for GitHub code-scanning ingestion."""

from __future__ import annotations

import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any


def _pkg_version() -> str:
    """Resolve the installed package version; never hardcode it."""
    try:
        return version("mas-sentry-toolkit")
    except PackageNotFoundError:
        return "0.0.0"


_SARIF_LEVELS: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def severity_to_sarif_level(severity: str) -> str:
    return _SARIF_LEVELS.get(severity.upper(), "note")


# GitHub code-scanning maps a numeric security-severity (0.0-10.0) on the rule
# to a band: >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, <=3.9 low. We anchor
# the band on the finding's textual severity so the GitHub badge stays coherent
# with our own label, then position the real composite anomaly score within
# that band so higher-scoring findings outrank lower ones inside the same band.
_SECURITY_SEVERITY_BANDS: dict[str, tuple[float, float]] = {
    "CRITICAL": (9.0, 10.0),
    "HIGH": (7.0, 8.9),
    "MEDIUM": (4.0, 6.9),
    "LOW": (0.1, 3.9),
    "INFO": (0.0, 0.0),
}


def _finding_total(f: dict[str, Any]) -> float | None:
    """Extract the 0..100 composite anomaly score, if this finding carries one."""
    total = (f.get("evidence") or {}).get("total")
    if total is None:
        return None
    try:
        return float(total)
    except (TypeError, ValueError):
        return None


def _security_severity(severity: str, total: float | None) -> float:
    """Map a finding to a GitHub security-severity number, band-anchored on severity.

    Scored findings (ABFP, total in 0..100) land at total/10 clamped into the band
    their textual severity implies. Non-scored findings (e.g. MCP checks) take the
    band midpoint. INFO maps to 0.0 (no security ranking).
    """
    lo, hi = _SECURITY_SEVERITY_BANDS.get(severity.upper(), (0.0, 0.0))
    if hi == 0.0:
        return 0.0
    if total is None:
        return round((lo + hi) / 2, 1)
    return round(min(hi, max(lo, total / 10.0)), 1)


def _driver_summary(dimensions: list[dict[str, Any]]) -> str:
    """Render fired scoring drivers as a compact one-line summary."""
    parts = [
        f"{d.get('name', '?')}({float(d.get('raw', 0.0)):.2f})" for d in dimensions if float(d.get("raw", 0.0)) > 0.0
    ]
    return "; drivers " + ", ".join(parts) if parts else ""


def to_sarif(findings: list[dict[str, Any]], tool_version: str | None = None) -> dict[str, Any]:
    if tool_version is None:
        tool_version = _pkg_version()
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in findings:
        check = f.get("check") or f.get("module") or "unknown"
        rule_id = f"MAS-SENTRY-{check.upper()}"
        level = severity_to_sarif_level(f["severity"])
        rule = rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": check},
                "defaultConfiguration": {"level": level},
            },
        )
        sev_num = _security_severity(f["severity"], _finding_total(f))
        if sev_num > 0.0:
            rprops = rule.setdefault("properties", {})
            if sev_num > float(rprops.get("security-severity", "0")):
                rprops["security-severity"] = f"{sev_num:.1f}"
        evidence = f.get("evidence") or {}
        dimensions = evidence.get("dimensions") or []
        message = f.get("detail", "") + _driver_summary(dimensions)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
        }
        properties: dict[str, Any] = {}
        if f.get("tags"):
            properties["tags"] = f["tags"]
        if dimensions:
            properties["drivers"] = dimensions
        if evidence.get("agent_id") is not None:
            properties["agent_id"] = evidence["agent_id"]
        if evidence.get("total") is not None:
            properties["score"] = evidence["total"]
        if evidence.get("blast_radius"):
            properties["blast_radius"] = evidence["blast_radius"]
        if evidence.get("z") is not None:
            # Effect size of a coordination signal: the number a triager
            # sorts and filters on, so it belongs in structured properties
            # rather than only inside the message text.
            properties["z"] = evidence["z"]
        if properties:
            result["properties"] = properties
        results.append(result)
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mas-sentry-toolkit",
                        "version": tool_version,
                        "informationUri": "https://github.com/evkir/mas-sentry-toolkit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(findings: list[dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(to_sarif(findings), indent=2))
