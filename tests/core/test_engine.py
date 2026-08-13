# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for core.finding, core.threat_engine, and core.adapters."""

import json

from mas_sentry.agentic.base import AgenticFinding, AsiCategory
from mas_sentry.agents.abfp.injection_propagation import PropagationFinding
from mas_sentry.agents.abfp.scoring import Severity as AbfpSeverity
from mas_sentry.core.adapters import (
    _to_sev,
    from_agentic,
    from_card_audit,
    from_mcp_check,
    from_propagation_finding,
)
from mas_sentry.core.finding import Finding, Severity, max_severity, rank
from mas_sentry.core.threat_engine import UnifiedThreatEngine
from mas_sentry.protocols.a2a.card_audit import CardFinding


def _f(
    title: str,
    sev: Severity = Severity.MEDIUM,
    target: str = "lab",
    evidence: dict | None = None,
) -> Finding:
    return Finding(
        module="test",
        title=title,
        detail="",
        severity=sev,
        target=target,
        evidence=evidence or {},
    )


# ─────────────── Finding model ───────────────


def test_rank_orders_severity() -> None:
    assert rank(Severity.INFO) < rank(Severity.LOW) < rank(Severity.MEDIUM)
    assert rank(Severity.MEDIUM) < rank(Severity.HIGH) < rank(Severity.CRITICAL)


def test_max_severity_empty_is_info() -> None:
    assert max_severity([]) == Severity.INFO


def test_finding_to_dict_is_json_serializable() -> None:
    f = _f("t", Severity.HIGH)
    d = f.to_dict()
    out = json.dumps(d, default=str)
    assert "HIGH" in out
    assert "t" in out


# ─────────────── UnifiedThreatEngine ───────────────


def test_engine_runs_registered_modules() -> None:
    engine = UnifiedThreatEngine()
    engine.register("a", lambda ctx: [_f("from-a")])
    engine.register("b", lambda ctx: [_f("from-b", Severity.HIGH)])
    run = engine.run(target="lab", ctx={})
    assert {f.title for f in run.findings} == {"from-a", "from-b"}
    assert run.max_severity == Severity.HIGH


def test_engine_dedupes_identical_findings() -> None:
    engine = UnifiedThreatEngine()
    engine.register("a", lambda ctx: [_f("dup")])
    engine.register("b", lambda ctx: [_f("dup")])
    run = engine.run(target="lab", ctx={})
    assert len(run.findings) == 1


def test_engine_keeps_findings_with_different_evidence() -> None:
    engine = UnifiedThreatEngine()
    engine.register("a", lambda ctx: [_f("same-title", evidence={"id": "x"})])
    engine.register("b", lambda ctx: [_f("same-title", evidence={"id": "y"})])
    run = engine.run(target="lab", ctx={})
    assert len(run.findings) == 2


def test_engine_handles_nested_evidence_for_dedupe() -> None:
    # Regression: plan used sorted(evidence.items()) which crashes on nested
    # dicts. We use json.dumps with sort_keys instead.
    nested = {"inner": {"a": 1, "b": [2, 3]}}
    engine = UnifiedThreatEngine()
    engine.register("a", lambda ctx: [_f("t", evidence=nested)])
    engine.register("b", lambda ctx: [_f("t", evidence=nested)])
    run = engine.run(target="lab", ctx={})
    assert len(run.findings) == 1


def test_engine_isolates_module_errors() -> None:
    def boom(_ctx: dict) -> list[Finding]:
        raise RuntimeError("intentional")

    engine = UnifiedThreatEngine()
    engine.register("ok", lambda ctx: [_f("good")])
    engine.register("boom", boom)
    run = engine.run(target="lab", ctx={})
    assert len(run.findings) == 1
    assert run.errors[0]["module"] == "boom"
    assert "intentional" in run.errors[0]["error"]
    # default: traceback NOT included
    assert "traceback" not in run.errors[0]


def test_engine_traceback_opt_in() -> None:
    def boom(_ctx: dict) -> list[Finding]:
        raise RuntimeError("trace please")

    engine = UnifiedThreatEngine(include_traceback=True)
    engine.register("boom", boom)
    run = engine.run(target="lab", ctx={})
    assert "traceback" in run.errors[0]
    assert "RuntimeError" in run.errors[0]["traceback"]


def test_engine_selected_filter_and_not_registered() -> None:
    engine = UnifiedThreatEngine()
    engine.register("a", lambda ctx: [_f("from-a")])
    engine.register("b", lambda ctx: [_f("from-b")])
    run = engine.run(target="lab", ctx={}, selected=["a", "ghost"])
    assert {f.title for f in run.findings} == {"from-a"}
    assert run.modules_ran == ["a"]
    assert any(e["module"] == "ghost" and e["error"] == "not_registered" for e in run.errors)


def test_engine_by_severity_filters() -> None:
    engine = UnifiedThreatEngine()
    engine.register(
        "a",
        lambda ctx: [
            _f("l", Severity.LOW),
            _f("h1", Severity.HIGH),
            _f("h2", Severity.HIGH),
        ],
    )
    run = engine.run(target="lab", ctx={})
    assert len(run.by_severity(Severity.HIGH)) == 2
    assert len(run.by_severity(Severity.LOW)) == 1
    assert len(run.by_severity(Severity.CRITICAL)) == 0


# ─────────────── Adapters ───────────────


def test_from_agentic_maps_module_and_tags() -> None:
    af = AgenticFinding(
        asi=AsiCategory.TOOL_MISUSE,
        severity="HIGH",
        title="t",
        detail="d",
        target="lab",
        cwe="CWE-78",
    )
    uf = from_agentic(af)
    assert uf.module == "agentic.tool_misuse"
    assert "ASI02_Tool_Misuse" in uf.tags
    assert "CWE-78" in uf.tags
    assert uf.severity == Severity.HIGH
    # captured_at preserved from source
    assert uf.captured_at == af.captured_at


def test_from_mcp_check_synthesizes_meaningful_title() -> None:
    entry = {
        "check": "ssrf",
        "severity": "CRITICAL",
        "detail": "fetch_url -> file:///etc/passwd",
    }
    uf = from_mcp_check(entry, target="lab.mcp")
    assert uf.module == "mcp.ssrf"
    assert uf.severity == Severity.CRITICAL
    # title should be more than just "ssrf" — should include detail snippet
    assert "ssrf" in uf.title and "fetch_url" in uf.title


def test_from_mcp_check_preserves_extra_fields_in_evidence() -> None:
    entry = {
        "check": "path_traversal",
        "severity": "HIGH",
        "detail": "leak",
        "tool": "read_file",
        "payload": "../../etc/passwd",
    }
    uf = from_mcp_check(entry, target="lab")
    assert uf.evidence == {"tool": "read_file", "payload": "../../etc/passwd"}


def test_from_card_audit_maps_to_a2a_module() -> None:
    cf = CardFinding(severity="HIGH", title="no auth", detail="x")
    uf = from_card_audit(cf, target="agent-x")
    assert uf.module == "a2a.card_audit"
    assert uf.severity == Severity.HIGH
    assert uf.target == "agent-x"
    assert "a2a" in uf.tags


def test_from_card_audit_propagates_poisoning_taxonomy() -> None:
    cf = CardFinding(
        severity="HIGH",
        title="Agent Card Poisoning: injection directive in description",
        detail="x",
        tags=["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"],
    )
    uf = from_card_audit(cf, target="agent-x")
    assert uf.tags == ["a2a", "ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"]


def test_to_sev_falls_back_to_info() -> None:
    assert _to_sev("nonsense") == Severity.INFO
    assert _to_sev("") == Severity.INFO
    assert _to_sev("HIGH") == Severity.HIGH
    assert _to_sev("high") == Severity.HIGH


def test_from_mcp_check_drift_taxonomy() -> None:
    f = from_mcp_check({"check": "tool_rug_pull", "severity": "HIGH", "detail": "x changed"}, "stdio://srv")
    assert f.tags == ["tool_rug_pull", "ASI04_Supply_Chain", "CWE-494", "STRIDE_Tampering", "AML.T0110"]
    g = from_mcp_check({"check": "tool_shadowing", "severity": "HIGH", "detail": "dup"}, "stdio://srv")
    assert "ASI02_Tool_Misuse" in g.tags and "STRIDE_Spoofing" in g.tags and "AML.T0110" in g.tags
    # non-security drift checks carry only their own category tag
    h = from_mcp_check({"check": "tool_baseline_captured", "severity": "INFO", "detail": "cap"}, "stdio://srv")
    assert h.tags == ["tool_baseline_captured"]


def test_from_mcp_check_injection_taxonomy() -> None:
    # Tool-poisoning findings (IPI in descriptor fields) carry the full
    # LLM-prompt-injection lens across all four taxonomies.
    p = from_mcp_check({"check": "tool_poisoning", "severity": "HIGH", "detail": "hidden directive"}, "stdio://srv")
    assert p.tags == ["tool_poisoning", "ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"]
    # Argument injection is command injection: CWE-77 + Tampering, deliberately no ATLAS.
    a = from_mcp_check({"check": "arg_injection", "severity": "CRITICAL", "detail": "&& id"}, "stdio://srv")
    assert a.tags == ["arg_injection", "ASI02_Tool_Misuse", "CWE-77", "STRIDE_Tampering"]
    assert not any(t.startswith("AML.") for t in a.tags)


def test_from_agentic_maps_atlas_technique() -> None:
    af = AgenticFinding(
        asi=AsiCategory.MEMORY_POISONING,
        severity="HIGH",
        title="memory poisoning",
        detail="persisted instruction",
        target="agent-x",
    )
    assert "AML.T0080" in from_agentic(af).tags
    # an ASI without a clean ATLAS match carries no AML tag
    af2 = AgenticFinding(asi=AsiCategory.UNTRACEABLE_ACTIONS, severity="LOW", title="t", detail="d", target="x")
    assert not any(t.startswith("AML.") for t in from_agentic(af2).tags)


def test_from_propagation_finding_maps_module_and_severity() -> None:
    pf = PropagationFinding(
        target="planner",
        origin="ingest",
        depth=2,
        tier="verbatim",
        chain=["ingest", "router", "planner"],
        severity=AbfpSeverity.CRITICAL,
    )
    uf = from_propagation_finding(pf, target="mesh://lab")
    assert uf.module == "abfp.propagation"
    assert uf.severity == Severity.CRITICAL
    assert uf.target == "mesh://lab"
    assert "ASI08_Cascading_Failure" in uf.tags
    assert uf.evidence["contaminated_agent"] == "planner"
    assert uf.evidence["origin"] == "ingest"
    assert uf.evidence["depth"] == 2
    assert uf.evidence["chain"] == ["ingest", "router", "planner"]


def test_from_propagation_finding_fuses_blast_radius() -> None:
    pf = PropagationFinding(
        target="planner",
        origin="ingest",
        depth=1,
        tier="directive",
        chain=["ingest", "planner"],
        severity=AbfpSeverity.HIGH,
    )
    br = {"direct": ["worker"], "transitive": ["worker", "logger"]}
    uf = from_propagation_finding(pf, target="mesh://lab", blast_radius=br)
    assert uf.severity == Severity.HIGH
    assert uf.evidence["blast_radius"] == br
