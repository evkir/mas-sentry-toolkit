# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Type aliases and typed utilities for MAS-Sentry-Toolkit.
"""

from typing import Any

# Common type aliases
FindingDict = dict[str, Any]
SessionSummary = dict[str, Any]
AgentProfile = dict[str, Any]
TopicMap = dict[str, list[str]]


def filter_findings(findings: list[FindingDict], severity: str) -> list[FindingDict]:
    """Return findings filtered by severity level."""
    return [f for f in findings if f.get("severity") == severity.upper()]


def get_critical(findings: list[FindingDict]) -> list[FindingDict]:
    """Return only CRITICAL severity findings."""
    return filter_findings(findings, "CRITICAL")


def get_high(findings: list[FindingDict]) -> list[FindingDict]:
    """Return only HIGH severity findings."""
    return filter_findings(findings, "HIGH")


def build_report_path(session_id: str, fmt: str = "json") -> str:
    """Build output report file path."""
    return f"reports/{session_id}.{fmt}"
