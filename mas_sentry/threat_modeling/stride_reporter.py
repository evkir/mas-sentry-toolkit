# SPDX-License-Identifier: AGPL-3.0-or-later
from typing import List
from .stride import STRIDEThreat, STRIDECategory, MAS_MQTT_THREATS


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def format_threat_report(threats: List[STRIDEThreat]) -> str:
    """Render STRIDE threats as a structured text report."""
    lines = ["=" * 60, "  STRIDE THREAT MODEL REPORT — MAS-Sentry-Toolkit", "=" * 60, ""]

    by_category: dict[STRIDECategory, List[STRIDEThreat]] = {}
    for t in threats:
        by_category.setdefault(t.category, []).append(t)

    for category, items in by_category.items():
        lines.append(f"\n[{category.value.upper()}]")
        lines.append("-" * 40)
        for t in sorted(items, key=lambda x: SEVERITY_ORDER.get(x.severity, 99)):
            lines.append(f"  [{t.severity}] {t.title}")
            lines.append(f"  Description : {t.description}")
            lines.append(f"  Mitigation  : {t.mitigation}")
            if t.cve_refs:
                lines.append(f"  CVE Refs    : {', '.join(t.cve_refs)}")
            lines.append("")

    lines.append(f"Total threats: {len(threats)}")
    return "\n".join(lines)


def get_threats_by_severity(severity: str) -> List[STRIDEThreat]:
    """Filter threat catalog by severity level."""
    return [t for t in MAS_MQTT_THREATS if t.severity == severity.upper()]


def get_threats_by_category(category: STRIDECategory) -> List[STRIDEThreat]:
    """Filter threat catalog by STRIDE category."""
    return [t for t in MAS_MQTT_THREATS if t.category == category]
