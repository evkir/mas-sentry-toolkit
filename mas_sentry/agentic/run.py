# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wire the static agentic modules into the UnifiedThreatEngine.

Only static-input modules are wired here. The live probes (goal hijack,
memory poisoning, resource exhaustion) need a live agent transport and are
driven separately.
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
from .base import AsiCategory


def run_static_scan(ctx: dict[str, Any]) -> list[Finding]:
    engine = UnifiedThreatEngine()
    target = ctx.get("target", "<unknown>")

    if ctx.get("tools"):
        engine.register(
            "tool_misuse",
            lambda c: [from_agentic(f) for f in tool_misuse.audit_tool_inventory(c["tools"], target)],
        )

    if ctx.get("token"):
        engine.register(
            "identity_abuse",
            lambda c: [from_agentic(f) for f in identity_abuse.audit_token(c["token"], target)],
        )

    if ctx.get("requirements_path"):
        rp = ctx["requirements_path"]
        sc_ctx = supply_chain.SupplyChainContext(requirements_path=Path(rp) if rp else None)
        engine.register(
            "supply_chain",
            lambda c: [from_agentic(f) for f in supply_chain.audit_supply_chain(sc_ctx, target)],
        )

    if ctx.get("call_graph"):
        engine.register(
            "cascade",
            lambda c: [from_agentic(f) for f in cascade.audit_call_graph(c["call_graph"], target)],
        )

    if ctx.get("action_log"):
        engine.register(
            "action_audit",
            lambda c: [from_agentic(f) for f in action_audit.audit_action_log(c["action_log"], target)],
        )

    if ctx.get("agent_response"):
        engine.register(
            "trust_exploit",
            lambda c: [from_agentic(f) for f in trust_exploit.audit_response(c["agent_response"], target)],
        )

    selected = _select(ctx.get("selected", "all"), engine.modules.keys())
    run = engine.run(target=target, ctx=ctx, selected=selected)
    return run.findings


# The --asi selector is a category number, but the module names no longer
# carry one, on purpose: a name that encodes a number goes stale the moment
# the list is renumbered, which is exactly what happened here. The number is
# resolved through the category values instead, so the selector keeps meaning
# what the published list says it means.
_MODULE_CATEGORY = {
    "tool_misuse": AsiCategory.TOOL_MISUSE,
    "identity_abuse": AsiCategory.IDENTITY_ABUSE,
    "supply_chain": AsiCategory.SUPPLY_CHAIN,
    "cascade": AsiCategory.CASCADING_FAILURE,
    "action_audit": AsiCategory.UNTRACEABLE_ACTIONS,
    "trust_exploit": AsiCategory.HUMAN_AGENT_TRUST,
}


def _select(asi: str, available: Any) -> list[str] | None:
    """Resolve a selector to module names, or None for "run everything".

    Accepts a category number ("asi04"), a full category tag
    ("ASI04_Supply_Chain") or a module name ("supply_chain"). An unknown
    selector resolves to an empty list, which runs nothing - the caller
    asked for a category this scan cannot cover, and silently running the
    whole suite instead would misreport what was scanned.
    """
    wanted = asi.lower().strip()
    if wanted in ("all", ""):
        return None
    return [
        module
        for module in available
        if module == wanted or _MODULE_CATEGORY.get(module, "").lower().startswith(wanted)
    ]
