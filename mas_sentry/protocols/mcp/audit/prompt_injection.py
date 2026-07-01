# SPDX-License-Identifier: AGPL-3.0-or-later
"""IPI scan of MCP tool definitions (description + parameter descriptions).

The pattern primitives live in mas_sentry.core.injection_scan (shared with the
ABFP live-traffic detector); this module keeps only the MCP-specific traversal
over the tool-definition shape.
"""

from __future__ import annotations

from typing import Any

from mas_sentry.core.injection_scan import InjectionMatch, scan_string

__all__ = ["InjectionMatch", "scan_string", "scan_tool_definitions"]


def scan_tool_definitions(
    tools: list[dict[str, Any]],
) -> dict[str, list[InjectionMatch]]:
    findings: dict[str, list[InjectionMatch]] = {}
    for t in tools:
        name = t.get("name", "<anonymous>")
        candidates = [t.get("description", "")]
        schema = t.get("inputSchema", {}) or {}
        # also inspect parameter descriptions
        for prop in (schema.get("properties") or {}).values():
            if isinstance(prop, dict):
                candidates.append(str(prop.get("description", "")))
        matches: list[InjectionMatch] = []
        for c in candidates:
            matches.extend(scan_string(c))
        if matches:
            findings[name] = matches
    return findings
