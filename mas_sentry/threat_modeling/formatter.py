# SPDX-License-Identifier: AGPL-3.0-or-later

from .stride import STRIDECategory, STRIDEThreat

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def format_stride_report(threats: list[STRIDEThreat]) -> str:
    """Render STRIDE threat list as a Markdown table."""
    lines = [
        "# STRIDE Threat Analysis — MAS/MQTT",
        "",
        "| # | Category | Severity | Title | Mitigation |",
        "|---|----------|----------|-------|------------|",
    ]
    sorted_threats = sorted(threats, key=lambda t: SEVERITY_ORDER.get(t.severity, 99))
    for i, t in enumerate(sorted_threats, 1):
        lines.append(f"| {i} | {t.category.value} | **{t.severity}** | {t.title} | {t.mitigation} |")

    lines += [
        "",
        f"**Total threats: {len(threats)}**",
        f"- CRITICAL: {sum(1 for t in threats if t.severity == 'CRITICAL')}",
        f"- HIGH:     {sum(1 for t in threats if t.severity == 'HIGH')}",
        f"- MEDIUM:   {sum(1 for t in threats if t.severity == 'MEDIUM')}",
        f"- LOW:      {sum(1 for t in threats if t.severity == 'LOW')}",
    ]
    return "\n".join(lines)


def map_abfp_finding_to_stride(finding: dict) -> STRIDECategory:
    """Auto-map an ABFP finding to the most relevant STRIDE category."""
    title = finding.get("title", "").lower()
    if "impersonat" in title or "spoof" in title or "duplicate" in title:
        return STRIDECategory.SPOOFING
    if "inject" in title or "poison" in title or "tamper" in title:
        return STRIDECategory.TAMPERING
    if "escalat" in title or "privilege" in title:
        return STRIDECategory.ELEVATION_OF_PRIVILEGE
    if "flood" in title or "dos" in title or "exhaust" in title:
        return STRIDECategory.DENIAL_OF_SERVICE
    if "disclosure" in title or "enum" in title or "leak" in title:
        return STRIDECategory.INFO_DISCLOSURE
    return STRIDECategory.REPUDIATION
