# SPDX-License-Identifier: AGPL-3.0-or-later
"""security-severity emission on SARIF rules for GitHub code-scanning ranking."""

from __future__ import annotations

from typing import Any

from mas_sentry.reporting.sarif import _security_severity, to_sarif


def _rule_props(doc: dict[str, Any], rule_id: str) -> dict[str, Any]:
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule = next(r for r in rules if r["id"] == rule_id)
    return rule.get("properties", {})


def test_security_severity_band_anchored_on_textual_severity() -> None:
    # A CRITICAL ABFP score of 85/100 is 8.5 raw, but its textual severity is
    # CRITICAL, so it must clamp up into GitHub's critical band (>=9.0).
    assert _security_severity("CRITICAL", 85.0) == 9.0
    assert _security_severity("CRITICAL", 92.0) == 9.2
    # HIGH score positions inside the high band.
    assert _security_severity("HIGH", 70.0) == 7.0
    assert _security_severity("HIGH", 84.0) == 8.4
    # MEDIUM / LOW within their bands.
    assert _security_severity("MEDIUM", 50.0) == 5.0
    assert _security_severity("LOW", 25.0) == 2.5
    # LOW score above the low ceiling clamps down to keep the badge coherent.
    assert _security_severity("LOW", 49.0) == 3.9
    # INFO carries no security ranking.
    assert _security_severity("INFO", 10.0) == 0.0


def test_security_severity_midpoint_for_non_scored_findings() -> None:
    # MCP checks have no composite total -> band midpoint.
    assert _security_severity("HIGH", None) == 8.0  # (7.0 + 8.9) / 2 -> 7.95 -> 8.0
    assert _security_severity("MEDIUM", None) == 5.5
    assert _security_severity("CRITICAL", None) == 9.5


def test_scored_abfp_finding_emits_security_severity_on_rule() -> None:
    findings = [
        {
            "check": "rogue",
            "severity": "CRITICAL",
            "detail": "rogue agent",
            "evidence": {"agent_id": "a1", "total": 92},
        }
    ]
    props = _rule_props(to_sarif(findings), "MAS-SENTRY-ROGUE")
    assert props["security-severity"] == "9.2"


def test_rule_takes_max_security_severity_across_findings() -> None:
    # Two findings share one rule_id; the rule must rank at the worst one.
    findings = [
        {"check": "rogue", "severity": "MEDIUM", "detail": "m", "evidence": {"total": 55}},
        {"check": "rogue", "severity": "CRITICAL", "detail": "c", "evidence": {"total": 90}},
    ]
    props = _rule_props(to_sarif(findings), "MAS-SENTRY-ROGUE")
    assert props["security-severity"] == "9.0"


def test_non_scored_mcp_finding_emits_band_midpoint() -> None:
    findings = [{"check": "tool_rug_pull", "severity": "HIGH", "detail": "drift", "evidence": {}}]
    props = _rule_props(to_sarif(findings), "MAS-SENTRY-TOOL_RUG_PULL")
    assert props["security-severity"] == "8.0"


def test_info_finding_emits_no_security_severity() -> None:
    findings = [{"check": "noise", "severity": "INFO", "detail": "fyi", "evidence": {}}]
    props = _rule_props(to_sarif(findings), "MAS-SENTRY-NOISE")
    assert "security-severity" not in props
