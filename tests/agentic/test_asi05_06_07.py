# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import json
import time
from typing import Any

from mas_sentry.agentic.action_audit import audit_action_log
from mas_sentry.agentic.base import AsiCategory
from mas_sentry.agentic.cascade import AgentEdge, audit_call_graph
from mas_sentry.agentic.pipeline import default_pipeline
from mas_sentry.agentic.resource_exhaustion import (
    ExhaustionTelemetry,
    evaluate_telemetry,
)
from mas_sentry.agentic.tool_misuse import ToolInventoryEntry


def _make_jwt(payload: dict[str, Any]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."


# ─────────────── ASI05 — cascading failure ───────────────


def test_cascade_detects_cycle_without_breaker() -> None:
    edges = [AgentEdge("a", "b"), AgentEdge("b", "c"), AgentEdge("c", "a")]
    findings = audit_call_graph(edges, target="lab")
    assert any("cycle" in f.title.lower() and f.severity == "HIGH" for f in findings)


def test_cascade_breaker_suppresses_cycle_finding() -> None:
    edges = [
        AgentEdge("a", "b", has_breaker=True),
        AgentEdge("b", "c", has_breaker=True),
        AgentEdge("c", "a", has_breaker=True),
    ]
    findings = audit_call_graph(edges, target="lab")
    assert all("cycle" not in f.title.lower() for f in findings)


def test_cascade_flags_high_in_degree() -> None:
    edges = [AgentEdge(f"caller{i}", "shared") for i in range(5)]
    findings = audit_call_graph(edges, target="lab")
    spof = [f for f in findings if "single point of failure" in f.title.lower()]
    assert spof
    assert spof[0].evidence["in_degree"] == 5
    assert spof[0].asi == AsiCategory.ASI05


def test_cascade_flags_retry_budget_gap() -> None:
    # 4 edges, all without retry budget → LOW finding (threshold = 3)
    edges = [
        AgentEdge("a", "b"),
        AgentEdge("a", "c"),
        AgentEdge("a", "d"),
        AgentEdge("a", "e"),
    ]
    findings = audit_call_graph(edges, target="lab")
    rb = [f for f in findings if "retry-budget" in f.title.lower()]
    assert rb
    assert rb[0].severity == "LOW"


# ─────────────── ASI06 — action audit ───────────────


def test_action_audit_flags_low_trace_coverage() -> None:
    # 0/10 traced → trace_ratio=0 → HIGH
    records = [{"tool": "t", "timestamp": i} for i in range(10)]
    findings = audit_action_log(records, target="lab")
    trace = [f for f in findings if "trace coverage" in f.title.lower()]
    assert trace
    assert trace[0].severity == "HIGH"
    assert trace[0].cwe == "CWE-778"


def test_action_audit_medium_severity_at_70_percent() -> None:
    # 7/10 traced → 0.7 ratio → between 0.5 (HIGH bound) and 0.9 (min) → MEDIUM
    records = [{"tool": "t", "traceparent": "x", "user_id": "u"} for _ in range(7)] + [
        {"tool": "t", "user_id": "u"} for _ in range(3)
    ]
    findings = audit_action_log(records, target="lab")
    trace = [f for f in findings if "trace coverage" in f.title.lower()]
    assert trace
    assert trace[0].severity == "MEDIUM"


def test_action_audit_full_coverage_no_findings() -> None:
    records = [{"tool": "t", "traceparent": "x", "user_id": "u"} for _ in range(10)]
    assert audit_action_log(records, target="lab") == []


# ─────────────── ASI07 — resource exhaustion ───────────────


def test_exhaustion_token_cap_breach() -> None:
    tel = [
        ExhaustionTelemetry(
            payload_name="token-bomb",
            response_tokens=100_000,
            elapsed_seconds=5,
            tool_calls_observed=0,
            refused=False,
        )
    ]
    findings = evaluate_telemetry(tel, target="lab")
    token_findings = [f for f in findings if "token cap" in f.title.lower()]
    assert token_findings
    assert token_findings[0].cwe == "CWE-400"
    assert token_findings[0].severity == "HIGH"


def test_exhaustion_latency_cap_breach() -> None:
    tel = [
        ExhaustionTelemetry(
            payload_name="slow",
            response_tokens=10,
            elapsed_seconds=60.0,
            tool_calls_observed=0,
            refused=False,
        )
    ]
    findings = evaluate_telemetry(tel, target="lab")
    lat = [f for f in findings if "latency cap" in f.title.lower()]
    assert lat
    assert lat[0].severity == "MEDIUM"


def test_exhaustion_tool_call_cap_breach() -> None:
    tel = [
        ExhaustionTelemetry(
            payload_name="fanout",
            response_tokens=10,
            elapsed_seconds=5,
            tool_calls_observed=50,
            refused=False,
        )
    ]
    findings = evaluate_telemetry(tel, target="lab")
    tools = [f for f in findings if "tool-call cap" in f.title.lower()]
    assert tools
    assert tools[0].cwe == "CWE-770"
    assert tools[0].severity == "HIGH"


def test_exhaustion_refused_payloads_skipped() -> None:
    tel = [
        ExhaustionTelemetry(
            payload_name="token-bomb",
            response_tokens=100_000,
            elapsed_seconds=999,
            tool_calls_observed=999,
            refused=True,
        )
    ]
    assert evaluate_telemetry(tel, target="lab") == []


# ─────────────── Pipeline integration ───────────────


def test_default_pipeline_registers_all_five_sync_modules() -> None:
    p = default_pipeline()
    assert set(p.modules.keys()) == {
        "asi02_tool_misuse",
        "asi03_identity_abuse",
        "asi05_cascade",
        "asi06_action_audit",
        "asi07_resource_exhaustion",
    }


def test_pipeline_end_to_end_all_asis() -> None:
    now = int(time.time())
    ctx = {
        "target": "lab",
        "tools": [
            ToolInventoryEntry(name="delete_all"),
            ToolInventoryEntry(name="http_post"),
        ],
        "token": _make_jwt({"sub": "agent:x", "iat": now, "exp": now + 7200}),
        "edges": [
            AgentEdge("a", "b"),
            AgentEdge("b", "c"),
            AgentEdge("c", "a"),
        ],
        "action_records": [{"tool": "t"} for _ in range(10)],
        "telemetry": [
            ExhaustionTelemetry(
                payload_name="p",
                response_tokens=100_000,
                elapsed_seconds=5,
                tool_calls_observed=0,
                refused=False,
            )
        ],
    }
    findings = default_pipeline().run(None, ctx)
    asis = {f.asi.name for f in findings}
    assert {"ASI02", "ASI03", "ASI05", "ASI06", "ASI07"}.issubset(asis)
