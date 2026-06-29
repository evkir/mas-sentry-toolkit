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
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": check},
                "defaultConfiguration": {"level": level},
            },
        )
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
