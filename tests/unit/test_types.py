from mas_sentry.core.types import (
    filter_findings,
    get_critical,
    get_high,
    build_report_path,
)

SAMPLE_FINDINGS = [
    {"severity": "CRITICAL", "title": "No auth"},
    {"severity": "HIGH", "title": "Wildcard sub"},
    {"severity": "MEDIUM", "title": "No TLS"},
    {"severity": "CRITICAL", "title": "Retained poison"},
]


def test_filter_findings_critical():
    result = filter_findings(SAMPLE_FINDINGS, "CRITICAL")
    assert len(result) == 2
    assert all(f["severity"] == "CRITICAL" for f in result)


def test_filter_findings_high():
    result = get_high(SAMPLE_FINDINGS)
    assert len(result) == 1
    assert result[0]["title"] == "Wildcard sub"


def test_get_critical():
    result = get_critical(SAMPLE_FINDINGS)
    assert len(result) == 2


def test_build_report_path():
    assert build_report_path("abc123") == "reports/abc123.json"
    assert build_report_path("abc123", "html") == "reports/abc123.html"


def test_filter_case_insensitive():
    result = filter_findings(SAMPLE_FINDINGS, "critical")
    assert len(result) == 2
