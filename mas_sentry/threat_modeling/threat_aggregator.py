from dataclasses import dataclass, field
from typing import List
from .stride import STRIDEThreat, MAS_THREAT_CATALOG


SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class ThreatScore:
    total_threats: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    weighted_score: float = 0.0
    risk_level: str = "LOW"
    top_threats: List[STRIDEThreat] = field(default_factory=list)


def aggregate_threats(threats: List[STRIDEThreat]) -> ThreatScore:
    score = ThreatScore(total_threats=len(threats))

    for t in threats:
        sev = t.severity
        if sev == "CRITICAL":
            score.critical_count += 1
        elif sev == "HIGH":
            score.high_count += 1
        elif sev == "MEDIUM":
            score.medium_count += 1
        else:
            score.low_count += 1
        score.weighted_score += t.cvss_score * SEVERITY_WEIGHT.get(sev, 1)

    if score.weighted_score > 0 and len(threats) > 0:
        score.weighted_score = round(score.weighted_score / len(threats), 2)

    if score.critical_count >= 2 or score.weighted_score >= 8.5:
        score.risk_level = "CRITICAL"
    elif score.critical_count >= 1 or score.weighted_score >= 7.0:
        score.risk_level = "HIGH"
    elif score.high_count >= 2 or score.weighted_score >= 5.0:
        score.risk_level = "MEDIUM"
    else:
        score.risk_level = "LOW"

    score.top_threats = sorted(threats, key=lambda t: t.cvss_score, reverse=True)[:3]
    return score
