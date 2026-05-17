# SPDX-License-Identifier: AGPL-3.0-or-later
import uuid
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class ScanSession:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    protocol: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    messages_captured: int = 0
    agents_discovered: int = 0

    def add_finding(self, severity: str, title: str, description: str, data: Any = None):
        self.findings.append({
            "id": len(self.findings) + 1,
            "severity": severity,
            "title": title,
            "description": description,
            "timestamp": datetime.utcnow().isoformat(),
            "data": data
        })

    def summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "protocol": self.protocol,
            "duration_seconds": (datetime.utcnow() - self.started_at).seconds,
            "findings_count": len(self.findings),
            "messages_captured": self.messages_captured,
            "agents_discovered": self.agents_discovered,
        }
