# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unified report model — aggregates all scan results into one object.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import json


@dataclass
class ReportMeta:
    session_id: str
    target: str
    protocol: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    toolkit_version: str = "0.1.0"
    operator: str = "mas-sentry"


@dataclass
class ProtocolFinding:
    title: str
    severity: str
    description: str
    evidence: Any = None
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class MASAuditReport:
    """
    Master report object — single source of truth for the full audit.
    Contains protocol findings, ABFP fingerprints, STRIDE threats.
    """
    meta: ReportMeta
    protocol_findings: List[ProtocolFinding] = field(default_factory=list)
    abfp_fingerprints: List[Dict] = field(default_factory=list)
    abfp_anomalies: List[Dict] = field(default_factory=list)
    stride_threats: List[Dict] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)

    def add_finding(self, title: str, severity: str,
                    description: str, evidence: Any = None,
                    remediation: str = ""):
        self.protocol_findings.append(ProtocolFinding(
            title=title, severity=severity,
            description=description,
            evidence=evidence, remediation=remediation
        ))

    def compute_statistics(self):
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.protocol_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        for a in self.abfp_anomalies:
            sev_counts[a.get("severity", "LOW")] = \
                sev_counts.get(a.get("severity", "LOW"), 0) + 1

        rogue = sum(
            1 for fp in self.abfp_fingerprints
            if fp.get("is_rogue", False)
        )
        max_score = max(
            (fp.get("anomaly_score", 0) for fp in self.abfp_fingerprints),
            default=0
        )
        self.statistics = {
            "total_findings": len(self.protocol_findings) + len(self.abfp_anomalies),
            "severity_breakdown": sev_counts,
            "agents_analyzed": len(self.abfp_fingerprints),
            "rogue_agents": rogue,
            "max_anomaly_score": round(max_score, 1),
            "stride_threats_mapped": len(self.stride_threats),
        }

    def to_dict(self) -> dict:
        self.compute_statistics()
        return {
            "meta": {
                "session_id": self.meta.session_id,
                "target": self.meta.target,
                "protocol": self.meta.protocol,
                "generated_at": self.meta.generated_at,
                "toolkit_version": self.meta.toolkit_version,
            },
            "statistics": self.statistics,
            "protocol_findings": [f.to_dict() for f in self.protocol_findings],
            "abfp_fingerprints": self.abfp_fingerprints,
            "abfp_anomalies": self.abfp_anomalies,
            "stride_threats": self.stride_threats,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, path: str):
        with open(path, "w") as f:
            f.write(self.to_json())
        print(f"[+] JSON report saved: {path}")
