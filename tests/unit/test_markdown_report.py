# SPDX-License-Identifier: AGPL-3.0-or-later
from mas_sentry.reporting.markdown_report import MarkdownReportGenerator
from mas_sentry.reporting.report_model import MASAuditReport, ReportMeta


def make_report():
    r = MASAuditReport(meta=ReportMeta(session_id="md-test", target="127.0.0.1", protocol="mqtt"))
    r.add_finding("Anon Access", "CRITICAL", "Broker open", remediation="Add auth")
    r.abfp_fingerprints = [{"agent_id": "test_agent", "message_count": 30, "anomaly_score": 5.0, "threat_flags": []}]
    return r


class TestMarkdownReport:
    def test_generates_markdown(self):
        md = MarkdownReportGenerator(make_report()).generate()
        assert "# MAS-Sentry Audit Report" in md

    def test_contains_session_id(self):
        md = MarkdownReportGenerator(make_report()).generate()
        assert "md-test" in md

    def test_contains_findings(self):
        md = MarkdownReportGenerator(make_report()).generate()
        assert "CRITICAL" in md
        assert "Anon Access" in md

    def test_contains_abfp(self):
        md = MarkdownReportGenerator(make_report()).generate()
        assert "test_agent" in md

    def test_save_creates_file(self, tmp_path):
        path = str(tmp_path / "test_report.md")
        MarkdownReportGenerator(make_report()).save(path)
        import os

        assert os.path.exists(path)
