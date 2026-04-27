"""
Maps ABFP anomaly findings and protocol scan results
to relevant STRIDE threats automatically.
"""
from typing import List, Dict
from rich.console import Console
from rich.table import Table

from .stride import STRIDEThreat, MAS_THREAT_CATALOG, SEVERITY_ORDER
from mas_sentry.agents.abfp_models import AgentFingerprint

console = Console()


class STRIDEMapper:
    """
    Automatic STRIDE threat mapper.
    Takes ABFP fingerprints + protocol findings → relevant STRIDE threats.
    """

    def __init__(self):
        self.mapped_threats: List[STRIDEThreat] = []

    def map_from_fingerprints(
        self, fingerprints: Dict[str, AgentFingerprint]
    ) -> List[STRIDEThreat]:
        """Map ABFP threat flags to STRIDE threats"""
        active_flags = set()
        for fp in fingerprints.values():
            for flag in fp.threat_flags:
                active_flags.add(flag)

        self.mapped_threats = []
        for threat in MAS_THREAT_CATALOG:
            if threat.abfp_flag and threat.abfp_flag in active_flags:
                self.mapped_threats.append(threat)

        console.print(
            f"[bold cyan][STRIDE] Mapped {len(self.mapped_threats)} "
            f"threats from {len(active_flags)} ABFP flags[/bold cyan]"
        )
        return self.mapped_threats

    def map_from_protocol_findings(
        self, findings: List[str]
    ) -> List[STRIDEThreat]:
        """Map protocol vulnerability names to STRIDE threats"""
        keyword_map = {
            "anonymous":    ["MAS-S-001", "MAS-I-001"],
            "retained":     ["MAS-T-001"],
            "will":         ["MAS-T-002"],
            "sys":          ["MAS-I-002"],
            "burst":        ["MAS-D-001"],
            "guest":        ["MAS-E-002"],
            "default":      ["MAS-E-002"],
        }
        matched_ids = set()
        for finding in findings:
            finding_lower = finding.lower()
            for keyword, threat_ids in keyword_map.items():
                if keyword in finding_lower:
                    matched_ids.update(threat_ids)

        new_threats = [
            t for t in MAS_THREAT_CATALOG
            if t.threat_id in matched_ids
            and t not in self.mapped_threats
        ]
        self.mapped_threats.extend(new_threats)
        return self.mapped_threats

    def print_stride_report(self):
        """Print full STRIDE threat mapping report"""
        if not self.mapped_threats:
            console.print("[green][STRIDE] No threats mapped[/green]")
            return

        sorted_threats = sorted(
            self.mapped_threats,
            key=lambda t: SEVERITY_ORDER.get(t.severity, 0),
            reverse=True
        )

        table = Table(title="[bold red]STRIDE Threat Report[/bold red]")
        table.add_column("ID",        style="dim",    width=12)
        table.add_column("Category",  style="cyan",   width=22)
        table.add_column("Title",     style="white",  width=35)
        table.add_column("Severity",  style="bold",   width=10)
        table.add_column("CVSS",      justify="right",width=6)
        table.add_column("Protocol",  style="yellow", width=8)

        for t in sorted_threats:
            sev_colors = {
                "CRITICAL": "bold red",
                "HIGH":     "red",
                "MEDIUM":   "yellow",
                "LOW":      "green",
            }
            color = sev_colors.get(t.severity, "white")
            table.add_row(
                t.threat_id,
                t.category.value,
                t.title[:34],
                f"[{color}]{t.severity}[/{color}]",
                str(t.cvss_score),
                t.affected_protocol.upper(),
            )
        console.print(table)

        console.print("\n[bold]Mitigations:[/bold]")
        for t in sorted_threats:
            console.print(
                f"  [cyan]{t.threat_id}[/cyan] "
                f"[dim]{t.title}[/dim]\n"
                f"    → {t.mitigation}"
            )

    def to_json(self) -> str:
        import json
        return json.dumps(
            [t.to_dict() for t in self.mapped_threats],
            indent=2
        )
