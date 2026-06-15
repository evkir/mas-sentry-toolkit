# SPDX-License-Identifier: AGPL-3.0-or-later
from mas_sentry.threat_modeling.stride import MAS_THREAT_CATALOG, STRIDECategory, STRIDEThreat
from mas_sentry.threat_modeling.stride_reporter import (
    format_threat_report,
    get_threats_by_category,
    get_threats_by_severity,
)


def _threat(severity="HIGH", category=STRIDECategory.SPOOFING):
    return STRIDEThreat(
        threat_id="T-1",
        category=category,
        title="Sample threat",
        description="desc",
        mitigation="fix it",
        severity=severity,
        cvss_score=7.5,
    )


def test_format_threat_report_contains_key_sections():
    report = format_threat_report([_threat("CRITICAL"), _threat("LOW")])
    assert "STRIDE THREAT MODEL REPORT" in report
    assert "[CRITICAL]" in report
    assert "Sample threat" in report
    assert "Total threats: 2" in report


def test_format_threat_report_sorts_by_severity():
    report = format_threat_report([_threat("LOW"), _threat("CRITICAL")])
    assert report.index("[CRITICAL]") < report.index("[LOW]")


def test_get_threats_by_severity_filters():
    high = get_threats_by_severity("high")
    assert high
    assert all(t.severity == "HIGH" for t in high)


def test_get_threats_by_category_filters():
    spoof = get_threats_by_category(STRIDECategory.SPOOFING)
    assert all(t.category == STRIDECategory.SPOOFING for t in spoof)
    assert all(t in MAS_THREAT_CATALOG for t in spoof)
