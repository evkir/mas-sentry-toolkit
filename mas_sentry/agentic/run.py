# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wire the static agentic modules into the UnifiedThreatEngine.

Only static-input modules are wired here (ASI02/03/05/06/08/09). The live
probes (ASI01 goal-hijack, ASI04 memory-poisoning, ASI07 resource-exhaustion)
need a live agent transport and are driven separately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mas_sentry.core.adapters import from_agentic
from mas_sentry.core.finding import Finding
from mas_sentry.core.threat_engine import UnifiedThreatEngine

from . import (
    action_audit,
    cascade,
    identity_abuse,
    supply_chain,
    tool_misuse,
    trust_exploit,
)


def run_static_scan(ctx: dict[str, Any]) -> list[Finding]:
    engine = UnifiedThreatEngine()
    target = ctx.get("target", "<unknown>")

    if ctx.get("tools"):
        engine.register(
            "asi02_tool_misuse",
            lambda c: [from_agentic(f) for f in tool_misuse.audit_tool_inventory(c["tools"], target)],
        )

    if ctx.get("token"):
        engine.register(
            "asi03_identity",
            lambda c: [from_agentic(f) for f in identity_abuse.audit_token(c["token"], target)],
        )

    if ctx.get("requirements_path"):
        rp = ctx["requirements_path"]
        sc_ctx = supply_chain.SupplyChainContext(requirements_path=Path(rp) if rp else None)
        engine.register(
            "asi08_supply",
            lambda c: [from_agentic(f) for f in supply_chain.audit_supply_chain(sc_ctx, target)],
        )

    if ctx.get("call_graph"):
        engine.register(
            "asi05_cascade",
            lambda c: [from_agentic(f) for f in cascade.audit_call_graph(c["call_graph"], target)],
        )

    if ctx.get("action_log"):
        engine.register(
            "asi06_audit",
            lambda c: [from_agentic(f) for f in action_audit.audit_action_log(c["action_log"], target)],
        )

    if ctx.get("agent_response"):
        engine.register(
            "asi09_trust",
            lambda c: [from_agentic(f) for f in trust_exploit.audit_response(c["agent_response"], target)],
        )

    selected = _select(ctx.get("selected", "all"), engine.modules.keys())
    run = engine.run(target=target, ctx=ctx, selected=selected)
    return run.findings


def _select(asi: str, available: Any) -> list[str] | None:
    asi = asi.lower().strip()
    if asi in ("all", ""):
        return None
    return [m for m in available if asi in m]
