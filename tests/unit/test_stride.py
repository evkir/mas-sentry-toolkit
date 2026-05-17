# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for STRIDE threat modeling.
Run: pytest tests/unit/test_stride.py -v
"""

import json

from mas_sentry.agents.abfp_models import AgentFingerprint
from mas_sentry.threat_modeling.stride import MAS_THREAT_CATALOG, STRIDECategory
from mas_sentry.threat_modeling.stride_mapper import STRIDEMapper


def make_fp_with_flags(*flags) -> AgentFingerprint:
    fp = AgentFingerprint(agent_id="test", first_seen=0, last_seen=60)
    fp.threat_flags = list(flags)
    return fp


class TestSTRIDECatalog:
    def test_catalog_not_empty(self):
        assert len(MAS_THREAT_CATALOG) >= 8

    def test_all_have_required_fields(self):
        for t in MAS_THREAT_CATALOG:
            assert t.threat_id.startswith("MAS-")
            assert t.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            assert t.cvss_score > 0
            assert len(t.mitigation) > 10

    def test_all_categories_covered(self):
        categories = {t.category for t in MAS_THREAT_CATALOG}
        assert STRIDECategory.SPOOFING in categories
        assert STRIDECategory.TAMPERING in categories
        assert STRIDECategory.ELEVATION_OF_PRIVILEGE in categories
        assert STRIDECategory.DENIAL_OF_SERVICE in categories

    def test_critical_threats_have_high_cvss(self):
        for t in MAS_THREAT_CATALOG:
            if t.severity == "CRITICAL":
                assert t.cvss_score >= 8.0


class TestSTRIDEMapper:
    def test_map_topic_escalation_flag(self):
        mapper = STRIDEMapper()
        fp = make_fp_with_flags("TOPIC_ESCALATION")
        threats = mapper.map_from_fingerprints({"agent": fp})
        ids = [t.threat_id for t in threats]
        assert "MAS-E-001" in ids

    def test_map_burst_flag(self):
        mapper = STRIDEMapper()
        fp = make_fp_with_flags("BURST_DETECTED")
        threats = mapper.map_from_fingerprints({"agent": fp})
        ids = [t.threat_id for t in threats]
        assert "MAS-D-001" in ids

    def test_map_no_baseline_flag(self):
        mapper = STRIDEMapper()
        fp = make_fp_with_flags("NO_BASELINE")
        threats = mapper.map_from_fingerprints({"agent": fp})
        ids = [t.threat_id for t in threats]
        assert "MAS-S-001" in ids

    def test_map_protocol_findings_anonymous(self):
        mapper = STRIDEMapper()
        threats = mapper.map_from_protocol_findings(["anonymous access allowed", "sys topics exposed"])
        ids = [t.threat_id for t in threats]
        assert "MAS-S-001" in ids
        assert "MAS-I-001" in ids
        assert "MAS-I-002" in ids

    def test_json_export_structure(self):
        mapper = STRIDEMapper()
        fp = make_fp_with_flags("BURST_DETECTED", "TOPIC_ESCALATION")
        mapper.map_from_fingerprints({"agent": fp})
        output = json.loads(mapper.to_json())
        assert isinstance(output, list)
        assert all("threat_id" in t for t in output)
        assert all("category" in t for t in output)
        assert all("cvss_score" in t for t in output)

    def test_no_flags_no_threats(self):
        mapper = STRIDEMapper()
        fp = make_fp_with_flags()
        threats = mapper.map_from_fingerprints({"agent": fp})
        assert len(threats) == 0
