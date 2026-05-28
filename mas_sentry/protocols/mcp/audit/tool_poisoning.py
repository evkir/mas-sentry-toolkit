# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tool-poisoning detector — runtime scan of live MCP server tool definitions."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..client import McpClient, ToolDef
from .prompt_injection import InjectionMatch, scan_string


@dataclass(frozen=True, slots=True)
class ToolPoisoningFinding:
    tool: str
    severity: str  # LOW / MEDIUM / HIGH / CRITICAL
    reasons: list[str] = field(default_factory=list)
    evidence: list[InjectionMatch] = field(default_factory=list)


def detect_tool_poisoning(client: McpClient) -> list[ToolPoisoningFinding]:
    tools = client.list_tools()
    findings: list[ToolPoisoningFinding] = []
    for t in tools:
        reasons: list[str] = []
        evidence: list[InjectionMatch] = []

        desc_hits = scan_string(t.description)
        if desc_hits:
            reasons.append("Suspicious patterns in tool description")
            evidence.extend(desc_hits)

        if _description_length_mismatch(t):
            reasons.append("Description size disproportionate to tool surface")

        if _schema_has_hidden_required(t):
            reasons.append("Hidden required parameter in inputSchema")

        if reasons:
            severity = _severity(len(reasons), len(evidence))
            findings.append(
                ToolPoisoningFinding(
                    tool=t.name,
                    severity=severity,
                    reasons=reasons,
                    evidence=evidence,
                )
            )
    return findings


def _description_length_mismatch(t: ToolDef) -> bool:
    # heuristic: very small surface (no params) + very long description → suspicious
    props = (t.input_schema or {}).get("properties") or {}
    return len(t.description) > 2000 and len(props) <= 1


def _schema_has_hidden_required(t: ToolDef) -> bool:
    schema = t.input_schema or {}
    req = set(schema.get("required") or [])
    props = set((schema.get("properties") or {}).keys())
    return bool(req - props)  # required keys not documented in properties


def _severity(reason_count: int, evidence_count: int) -> str:
    score = reason_count + evidence_count
    if score >= 4:
        return "CRITICAL"
    if score >= 3:
        return "HIGH"
    if score == 2:
        return "MEDIUM"
    return "LOW"
