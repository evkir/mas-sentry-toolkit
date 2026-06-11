# SPDX-License-Identifier: AGPL-3.0-or-later
"""SARIF v2.1.0 emitter — for GitHub code-scanning ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SARIF_LEVELS: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def severity_to_sarif_level(severity: str) -> str:
    return _SARIF_LEVELS.get(severity.upper(), "note")


def to_sarif(findings: list[dict[str, Any]], tool_version: str = "0.2.0.dev0") -> dict[str, Any]:
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
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f.get("detail", "")},
        }
        if f.get("tags"):
            result["properties"] = {"tags": f["tags"]}
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
