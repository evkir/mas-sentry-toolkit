# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for threat scoring aggregation.
"""
from mas_sentry.threat_modeling.stride import MAS_THREAT_CATALOG
from mas_sentry.threat_modeling.threat_aggregator import (
    aggregate_threats, ThreatScore
)


def get_by_severity(severity: str):
    return [t for t in MAS_THREAT_CATALOG if t.severity == severity]


class TestThreatAggregator:
    def test_empty_returns_zero_score(self):
        result = aggregate_threats([])
        assert result.total_threats == 0
        assert result.weighted_score == 0.0
        assert result.risk_level == "LOW"

    def test_counts_by_severity(self):
        threats = get_by_severity("CRITICAL") + get_by_severity("HIGH")
        result = aggregate_threats(threats)
        assert result.critical_count == len(get_by_severity("CRITICAL"))
        assert result.high_count == len(get_by_severity("HIGH"))

    def test_two_critical_gives_critical_risk(self):
        criticals = get_by_severity("CRITICAL")[:2]
        result = aggregate_threats(criticals)
        assert result.risk_level == "CRITICAL"

    def test_one_critical_gives_high_risk(self):
        one_critical = get_by_severity("CRITICAL")[:1]
        result = aggregate_threats(one_critical)
        assert result.risk_level in ["CRITICAL", "HIGH"]

    def test_top_threats_max_three(self):
        result = aggregate_threats(MAS_THREAT_CATALOG)
        assert len(result.top_threats) <= 3

    def test_top_threats_sorted_by_cvss(self):
        result = aggregate_threats(MAS_THREAT_CATALOG)
        scores = [t.cvss_score for t in result.top_threats]
        assert scores == sorted(scores, reverse=True)

    def test_total_threats_count(self):
        result = aggregate_threats(MAS_THREAT_CATALOG)
        assert result.total_threats == len(MAS_THREAT_CATALOG)
