# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class AsiCategory(StrEnum):
    ASI01 = "ASI01_Goal_Hijack"
    ASI02 = "ASI02_Tool_Misuse"
    ASI03 = "ASI03_Identity_Abuse"
    ASI04 = "ASI04_Memory_Poisoning"
    ASI05 = "ASI05_Cascading_Failure"
    ASI06 = "ASI06_Untraceable_Actions"
    ASI07 = "ASI07_Resource_Exhaustion"
    ASI08 = "ASI08_Supply_Chain"
    ASI09 = "ASI09_Human_Agent_Trust"
    ASI10 = "ASI10_Rogue_Agent"


@dataclass(frozen=True, slots=True)
class AgenticFinding:
    asi: AsiCategory
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    detail: str
    target: str
    evidence: dict[str, Any] = field(default_factory=dict)
    cwe: str | None = None
    captured_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
