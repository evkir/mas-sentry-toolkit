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
from mas_sentry.core.threat_engine import EngineRun, UnifiedThreatEngine

from . import (
    action_audit,
    cascade,
    identity_abuse,
    supply_chain,
    tool_misuse,
    trust_exploit,
)
from .base import AsiCategory


def run_static_scan(ctx: dict[str, Any]) -> EngineRun:
    """Run the wired static modules and return the run, not just its findings.

    The run carries modules_ran, which is the only thing separating
    "nothing was wrong" from "nothing was checked". Returning the findings
    alone collapsed those two into the same empty list, and every caller
    reported the second as the first.
    """
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
    return engine.run(target=target, ctx=ctx, selected=selected)


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


# What feeds each wired module. Only the first three have a CLI option; the
# rest are wired for library callers that already hold the object. The value
# is prose rather than a flag alone so the message can say which is which.
_MODULE_INPUT = {
    "tool_misuse": "--tools-file",
    "identity_abuse": "--token",
    "supply_chain": "--requirements",
    "cascade": "a call graph, which this command cannot supply",
    "action_audit": "an action log, which this command cannot supply",
    "trust_exploit": "an agent response, which this command cannot supply",
}


def no_coverage_reason(asi: str) -> str:
    """Say why a selector ran nothing, so the caller is not told it ran clean.

    Resolved against every wired module rather than the registered ones,
    because the useful distinction is between a category this scan knows and
    was not given the input for, and one it does not implement at all. Both
    produce an empty selection, and only the first is worth a flag name.
    """
    wanted = asi.lower().strip()
    if wanted in ("all", ""):
        return (
            "no check ran: --asi all selects every wired module and none of them was "
            "given its input. Pass --requirements, --tools-file or --token."
        )
    modules = _select(wanted, _MODULE_CATEGORY.keys()) or []
    if not modules:
        return (
            f"no check ran: --asi {asi} matches no module this command wires. "
            "The README ASI table says where each category is covered."
        )
    names = ", ".join(modules)
    inputs = ", ".join(dict.fromkeys(_MODULE_INPUT[m] for m in modules))
    return f"no check ran: --asi {asi} selects {names}, and its input was not given ({inputs})."
