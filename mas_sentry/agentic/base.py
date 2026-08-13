# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class AsiCategory(StrEnum):
    """Category identifiers emitted as finding tags.

    The values track the published OWASP Top 10 for Agentic Applications
    2026 (ASI01-ASI10). MST previously carried a pre-release ordering in
    which supply chain was ASI08, memory poisoning ASI04 and cascading
    failure ASI05; those numbers now belong to other categories, so a
    consumer filtering SARIF by number was reading the wrong lens.

    Members are named after the category rather than its number so that a
    future renumbering cannot leave the symbol asserting something the
    value no longer says.

    Two detectors have no home in the published list: untraceable actions
    and resource exhaustion were dropped between the draft and the release.
    They keep an MST_ prefix rather than an ASI number, because occupying a
    number that now means something else is worse than carrying none.
    """

    GOAL_HIJACK = "ASI01_Goal_Hijack"
    TOOL_MISUSE = "ASI02_Tool_Misuse"
    IDENTITY_ABUSE = "ASI03_Identity_Abuse"
    SUPPLY_CHAIN = "ASI04_Supply_Chain"
    CODE_EXECUTION = "ASI05_Unexpected_Code_Execution"
    MEMORY_POISONING = "ASI06_Memory_Poisoning"
    INSECURE_COMMUNICATION = "ASI07_Insecure_Communication"
    CASCADING_FAILURE = "ASI08_Cascading_Failure"
    HUMAN_AGENT_TRUST = "ASI09_Human_Agent_Trust"
    ROGUE_AGENT = "ASI10_Rogue_Agent"
    UNTRACEABLE_ACTIONS = "MST_Untraceable_Actions"
    RESOURCE_EXHAUSTION = "MST_Resource_Exhaustion"


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
