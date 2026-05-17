# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from typing import List
from .stride import STRIDEThreat, MAS_THREAT_CATALOG

CATALOG = {t.threat_id: t for t in MAS_THREAT_CATALOG}

FLAG_TO_THREAT_IDS = {
    "TOPIC_ESCALATION": ["MAS-E-001"],
    "ACL_BYPASS":       ["MAS-E-002"],
    "BURST_DETECTED":   ["MAS-D-001"],
    "NO_BASELINE":      ["MAS-S-001"],
    "CLONE_DETECTED":   ["MAS-S-002"],
    "RETAIN_POISON":    ["MAS-T-001"],
    "PAYLOAD_INJECT":   ["MAS-T-002"],
    "NO_SIGNING":       ["MAS-R-001"],
    "WILDCARD_ENUM":    ["MAS-I-001"],
    "SYS_EXPOSED":      ["MAS-I-002"],
}

PROTOCOL_FINDING_TO_THREAT_IDS = {
    "anonymous access allowed": ["MAS-S-001"],
    "sys topics exposed":       ["MAS-I-001", "MAS-I-002"],
    "no tls":                   ["MAS-T-001"],
    "wildcard subscription":    ["MAS-I-001"],
    "retained message":         ["MAS-T-001"],
}


class STRIDEMapper:
    def __init__(self):
        self._threats: List[STRIDEThreat] = []

    def map_from_fingerprints(self, fingerprints: dict) -> List[STRIDEThreat]:
        seen = set()
        for fp in fingerprints.values():
            for flag in getattr(fp, "threat_flags", []):
                for tid in FLAG_TO_THREAT_IDS.get(flag, []):
                    if tid not in seen and tid in CATALOG:
                        self._threats.append(CATALOG[tid])
                        seen.add(tid)
        return self._threats

    def map_from_protocol_findings(self, findings: List[str]) -> List[STRIDEThreat]:
        seen = {t.threat_id for t in self._threats}
        for finding in findings:
            for keyword, tids in PROTOCOL_FINDING_TO_THREAT_IDS.items():
                if keyword in finding.lower():
                    for tid in tids:
                        if tid not in seen and tid in CATALOG:
                            self._threats.append(CATALOG[tid])
                            seen.add(tid)
        return self._threats

    def to_json(self) -> str:
        return json.dumps([
            {
                "threat_id": t.threat_id,
                "category": t.category.value,
                "title": t.title,
                "severity": t.severity,
                "cvss_score": t.cvss_score,
                "mitigation": t.mitigation,
            }
            for t in self._threats
        ], indent=2)
