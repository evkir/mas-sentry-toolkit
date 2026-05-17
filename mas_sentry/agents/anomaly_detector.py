# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ABFP Phase 3 — Anomaly Detection Engine.
Detects behavioral deviations, rogue agents, privilege escalation.
"""

from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .abfp_models import AgentFingerprint, BehavioralBaseline

console = Console()


@dataclass
class AnomalyFinding:
    """Single anomaly finding from the detector"""

    agent_id: str
    finding_type: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    score_contribution: float
    description: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "score_contribution": round(self.score_contribution, 2),
            "description": self.description,
            "evidence": self.evidence,
        }


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


class AnomalyDetector:
    """
    ABFP Phase 3: Behavioral anomaly detection.

    Detects:
    - Z-score timing deviation
    - New topic emergence (privilege escalation)
    - Payload size spikes
    - Entropy anomalies (encryption/obfuscation)
    - Burst attack patterns
    - Rogue agents (no matching baseline)
    """

    # Thresholds
    TIMING_ZSCORE_THRESHOLD = 2.5
    PAYLOAD_SPIKE_RATIO = 3.0
    ENTROPY_HIGH_THRESHOLD = 7.0  # near-random = encrypted/compressed
    ENTROPY_LOW_THRESHOLD = 0.5  # near-zero = suspicious repetition
    BURST_INTERVAL_MS = 50.0

    def __init__(self, baselines: dict[str, BehavioralBaseline] | None = None):
        self.baselines = baselines or {}
        self.findings: list[AnomalyFinding] = []

    def _add(
        self,
        agent_id: str,
        finding_type: str,
        severity: str,
        score: float,
        description: str,
        evidence: dict | None = None,
    ):
        f = AnomalyFinding(
            agent_id=agent_id,
            finding_type=finding_type,
            severity=severity,
            score_contribution=score,
            description=description,
            evidence=evidence or {},
        )
        self.findings.append(f)
        color = SEVERITY_COLORS.get(severity, "white")
        console.print(f"[{color}][{severity}] {agent_id}: {description}[/{color}]")
        return f

    def analyze(self, fingerprints: dict[str, AgentFingerprint]) -> dict[str, AgentFingerprint]:
        """Run all anomaly checks on collected fingerprints"""
        self.findings.clear()
        console.print("[bold cyan][ABFP] Phase 3 — Running anomaly detection...[/bold cyan]")

        for _agent_id, fp in fingerprints.items():
            score = 0.0
            fp.threat_flags.clear()

            score += self._check_timing(fp)
            score += self._check_payload_spike(fp)
            score += self._check_entropy(fp)
            score += self._check_burst(fp)
            score += self._check_new_topics(fp)
            score += self._check_rogue(fp)

            fp.anomaly_score = min(score, 100.0)
            fp.is_rogue = fp.anomaly_score >= 70.0

        return fingerprints

    def _check_timing(self, fp: AgentFingerprint) -> float:
        """Z-score based timing deviation from baseline"""
        score = 0.0
        baseline = self.baselines.get(fp.agent_id)
        if not baseline or baseline.expected_interval_ms <= 0:
            return 0.0

        expected = baseline.expected_interval_ms
        actual = fp.timing.mean_interval_ms
        std = fp.timing.std_interval_ms or 1.0

        z_score = abs(actual - expected) / std
        if z_score > self.TIMING_ZSCORE_THRESHOLD:
            contrib = min(z_score * 5.0, 25.0)
            score += contrib
            fp.add_threat_flag("TIMING_DEVIATION")
            self._add(
                fp.agent_id,
                "TIMING_DEVIATION",
                "HIGH" if z_score > 5 else "MEDIUM",
                contrib,
                f"Timing z-score={z_score:.1f} (expected={expected:.0f}ms, actual={actual:.0f}ms)",
                {"z_score": round(z_score, 2), "expected_ms": expected, "actual_ms": actual},
            )
        return score

    def _check_payload_spike(self, fp: AgentFingerprint) -> float:
        """Detect abnormal payload size increase"""
        score = 0.0
        baseline = self.baselines.get(fp.agent_id)
        if not baseline or baseline.expected_payload_size <= 0:
            return 0.0

        ratio = fp.payload.mean_size_bytes / baseline.expected_payload_size
        if ratio > self.PAYLOAD_SPIKE_RATIO:
            contrib = min((ratio - 1) * 8.0, 20.0)
            score += contrib
            fp.add_threat_flag("PAYLOAD_SPIKE")
            self._add(
                fp.agent_id,
                "PAYLOAD_SPIKE",
                "HIGH",
                contrib,
                f"Payload {ratio:.1f}x larger than baseline "
                f"({fp.payload.mean_size_bytes:.0f}B vs {baseline.expected_payload_size:.0f}B)",
                {"ratio": round(ratio, 2)},
            )
        return score

    def _check_entropy(self, fp: AgentFingerprint) -> float:
        """Detect unusually high or low payload entropy"""
        score = 0.0
        entropy = fp.payload.entropy_score

        if entropy >= self.ENTROPY_HIGH_THRESHOLD:
            fp.add_threat_flag("HIGH_ENTROPY")
            score += 15.0
            self._add(
                fp.agent_id,
                "HIGH_ENTROPY",
                "MEDIUM",
                15.0,
                f"Entropy={entropy:.2f} — payload may be encrypted or compressed",
                {"entropy": entropy},
            )
        elif 0 < entropy <= self.ENTROPY_LOW_THRESHOLD:
            fp.add_threat_flag("LOW_ENTROPY")
            score += 10.0
            self._add(
                fp.agent_id,
                "LOW_ENTROPY",
                "LOW",
                10.0,
                f"Entropy={entropy:.2f} — suspiciously repetitive payload",
                {"entropy": entropy},
            )
        return score

    def _check_burst(self, fp: AgentFingerprint) -> float:
        """Detect burst messaging (potential DoS or flood)"""
        if fp.timing.burst_detected:
            fp.add_threat_flag("BURST_DETECTED")
            self._add(
                fp.agent_id,
                "BURST_DETECTED",
                "HIGH",
                20.0,
                f"Burst pattern: min_interval={fp.timing.min_interval_ms:.1f}ms < {self.BURST_INTERVAL_MS}ms",
                {"min_interval_ms": fp.timing.min_interval_ms},
            )
            return 20.0
        return 0.0

    def _check_new_topics(self, fp: AgentFingerprint) -> float:
        """Detect new topics not in baseline (privilege escalation)"""
        score = 0.0
        baseline = self.baselines.get(fp.agent_id)
        if not baseline:
            return 0.0

        new_topics = set(fp.unique_topics) - set(baseline.known_topics)
        if new_topics:
            contrib = min(len(new_topics) * 15.0, 45.0)
            score += contrib
            fp.add_threat_flag("TOPIC_ESCALATION")
            self._add(
                fp.agent_id,
                "TOPIC_ESCALATION",
                "CRITICAL",
                contrib,
                f"Agent publishing to {len(new_topics)} new topic(s) outside baseline",
                {"new_topics": list(new_topics)},
            )
        return score

    def _check_rogue(self, fp: AgentFingerprint) -> float:
        """Flag agents with no matching baseline as potential rogue"""
        if fp.agent_id not in self.baselines and fp.confidence >= 0.5:
            fp.add_threat_flag("NO_BASELINE")
            self._add(
                fp.agent_id,
                "NO_BASELINE",
                "MEDIUM",
                10.0,
                "Agent has no known-good behavioral baseline on record",
                {"confidence": fp.confidence},
            )
            return 10.0
        return 0.0

    def print_report(self, fingerprints: dict[str, AgentFingerprint]):
        """Print full anomaly detection report"""
        console.print()
        console.print(Panel("[bold red]ABFP ANOMALY DETECTION REPORT[/bold red]", style="red"))

        # Summary table
        table = Table(title="Agent Risk Summary")
        table.add_column("Agent ID", style="cyan")
        table.add_column("Messages", justify="right")
        table.add_column("Anomaly Score", justify="right")
        table.add_column("Risk Level", justify="center")
        table.add_column("Flags", style="yellow")

        for agent_id, fp in sorted(fingerprints.items(), key=lambda x: x[1].anomaly_score, reverse=True):
            score = fp.anomaly_score
            if score >= 70:
                risk = "[bold red]CRITICAL[/bold red]"
            elif score >= 40:
                risk = "[red]HIGH[/red]"
            elif score >= 20:
                risk = "[yellow]MEDIUM[/yellow]"
            else:
                risk = "[green]LOW[/green]"

            table.add_row(
                agent_id,
                str(fp.message_count),
                f"{score:.1f}/100",
                risk,
                ", ".join(fp.threat_flags) or "—",
            )
        console.print(table)

        # Detailed findings
        if self.findings:
            console.print(f"\n[bold]Detailed Findings ({len(self.findings)} total):[/bold]")
            for f in self.findings:
                color = SEVERITY_COLORS.get(f.severity, "white")
                console.print(f"  [{color}][{f.severity}][/{color}] [cyan]{f.agent_id}[/cyan] — {f.description}")

    def to_json(self) -> str:
        import json

        return json.dumps([f.to_dict() for f in self.findings], indent=2)

    def save_report(self, path: str):
        with open(path, "w") as f:
            f.write(self.to_json())
        console.print(f"[green][ABFP] Report saved to {path}[/green]")
