# SPDX-License-Identifier: AGPL-3.0-or-later
from mas_sentry.threat_modeling.abfp_stride_mapper import map_finding_to_stride, map_session_findings
from mas_sentry.threat_modeling.stride import STRIDECategory


def test_map_known_finding_type():
    threat = map_finding_to_stride({"type": "duplicate_client_id", "severity": "HIGH"})
    assert threat is not None
    assert threat.category == STRIDECategory.SPOOFING
    assert threat.threat_id == "ABFP-DUPLICATE_CLIENT_ID"
    assert threat.cvss_score == 7.5


def test_map_unknown_finding_type_returns_none():
    assert map_finding_to_stride({"type": "totally_unknown"}) is None


def test_map_session_findings_skips_unknown():
    findings = [
        {"type": "duplicate_client_id", "severity": "HIGH"},
        {"type": "message_flood", "severity": "CRITICAL"},
        {"type": "totally_unknown"},
    ]
    threats = map_session_findings(findings)
    assert len(threats) == 2
    cats = {t.category for t in threats}
    assert STRIDECategory.SPOOFING in cats
    assert STRIDECategory.DENIAL_OF_SERVICE in cats
