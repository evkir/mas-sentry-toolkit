# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pluggable agentic-scan pipeline. Modules opt-in by name.

Only synchronous static-input modules are registered here. ASI01
(goal_hijack) and ASI04 (memory_poisoning) require live agent interaction
across multiple turns and are orchestrated by their own drivers, not by
this pipeline.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .base import AgenticFinding

ModuleFn = Callable[[dict[str, Any]], list[AgenticFinding]]


@dataclass(slots=True)
class Pipeline:
    modules: dict[str, ModuleFn] = field(default_factory=dict)

    def register(self, name: str, fn: ModuleFn) -> None:
        self.modules[name] = fn

    def run(self, selected: list[str] | None, ctx: dict[str, Any]) -> list[AgenticFinding]:
        names = selected or list(self.modules.keys())
        findings: list[AgenticFinding] = []
        for n in names:
            fn = self.modules.get(n)
            if fn:
                findings.extend(fn(ctx))
        return findings


def _run_tool_misuse(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .tool_misuse import audit_tool_inventory

    return audit_tool_inventory(ctx.get("tools", []), ctx.get("target", "<unknown>"))


def _run_identity_abuse(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .identity_abuse import audit_token

    token = ctx.get("token", "")
    if not token:
        return []
    return audit_token(token, ctx.get("target", "<unknown>"))


def default_pipeline() -> Pipeline:
    p = Pipeline()
    p.register("asi02_tool_misuse", _run_tool_misuse)
    p.register("asi03_identity_abuse", _run_identity_abuse)
    return p
