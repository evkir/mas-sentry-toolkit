# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pluggable agentic-scan pipeline. Modules opt-in by name.

Only synchronous static-input modules are registered here. ASI01
(goal_hijack) and ASI06 (memory_poisoning) require live agent interaction
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


def _run_cascade(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .cascade import audit_call_graph

    return audit_call_graph(ctx.get("edges", []), ctx.get("target", "<unknown>"))


def _run_action_audit(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .action_audit import audit_action_log

    return audit_action_log(ctx.get("action_records", []), ctx.get("target", "<unknown>"))


def _run_resource_exhaustion(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .resource_exhaustion import evaluate_telemetry

    return evaluate_telemetry(ctx.get("telemetry", []), ctx.get("target", "<unknown>"))


def _run_supply_chain(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .supply_chain import SupplyChainContext, audit_supply_chain

    sc_ctx = ctx.get("supply_chain")
    if sc_ctx is None:
        return []
    if not isinstance(sc_ctx, SupplyChainContext):
        return []
    return audit_supply_chain(sc_ctx, ctx.get("target", "<unknown>"))


def _run_trust_exploit(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .trust_exploit import AgentResponse, audit_response

    resp = ctx.get("agent_response")
    if resp is None:
        return []
    if not isinstance(resp, AgentResponse):
        return []
    return audit_response(resp, ctx.get("target", "<unknown>"))


def _run_rogue_agent(ctx: dict[str, Any]) -> list[AgenticFinding]:
    from .rogue_agent import audit_for_rogue_agents

    baseline = ctx.get("baseline_graph")
    current = ctx.get("current_graph")
    if baseline is None or current is None:
        return []
    return audit_for_rogue_agents(baseline, current, ctx.get("target", "<unknown>"))


def default_pipeline() -> Pipeline:
    p = Pipeline()
    p.register("tool_misuse", _run_tool_misuse)
    p.register("identity_abuse", _run_identity_abuse)
    p.register("cascade", _run_cascade)
    p.register("action_audit", _run_action_audit)
    p.register("resource_exhaustion", _run_resource_exhaustion)
    p.register("supply_chain", _run_supply_chain)
    p.register("trust_exploit", _run_trust_exploit)
    p.register("rogue_agent", _run_rogue_agent)
    return p
