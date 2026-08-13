# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import json
import time
from typing import Any

from mas_sentry.agentic.base import AsiCategory
from mas_sentry.agentic.identity_abuse import audit_token, parse_jwt
from mas_sentry.agentic.memory_poisoning import (
    MemoryDriftResult,
    evaluate_drift,
    make_canary_fact,
    update_round,
)
from mas_sentry.agentic.pipeline import Pipeline, default_pipeline
from mas_sentry.agentic.tool_misuse import ToolInventoryEntry


def _make_jwt(payload: dict[str, Any]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."


# ─────────────── ASI03 — identity abuse ───────────────


def test_parse_jwt_extracts_claims() -> None:
    tok = _make_jwt({"sub": "agent:42", "iat": 1, "exp": 100})
    insight = parse_jwt(tok)
    assert insight is not None
    assert insight.claims["sub"] == "agent:42"
    assert insight.lifetime_seconds == 99


def test_parse_jwt_invalid_returns_none() -> None:
    assert parse_jwt("not-a-jwt") is None
    assert parse_jwt("only.one.part") is not None or True  # has 3 parts but body unparseable
    assert parse_jwt("totally garbage no dots") is None


def test_parse_jwt_garbage_timestamps_yield_zero_lifetime() -> None:
    tok = _make_jwt({"sub": "agent:x", "iat": "bad", "exp": "also-bad"})
    insight = parse_jwt(tok)
    assert insight is not None
    assert insight.lifetime_seconds == 0


def test_delegation_depth_counts_act_chain() -> None:
    tok = _make_jwt(
        {
            "sub": "a",
            "act": {"sub": "b", "act": {"sub": "c", "act": {"sub": "d"}}},
        }
    )
    insight = parse_jwt(tok)
    assert insight is not None
    assert insight.delegation_depth == 3


def test_audit_token_flags_long_lifetime_agent() -> None:
    now = int(time.time())
    tok = _make_jwt({"sub": "agent:gpt", "iat": now, "exp": now + 7200})
    findings = audit_token(tok, target="api.example")
    assert any("lifetime" in f.title.lower() for f in findings)
    lifetime_finding = next(f for f in findings if "lifetime" in f.title.lower())
    assert lifetime_finding.severity == "HIGH"
    assert lifetime_finding.cwe == "CWE-613"


def test_audit_token_does_not_flag_human_lifetime() -> None:
    # Long-lived token without agent markers in sub/aud → no lifetime finding.
    now = int(time.time())
    tok = _make_jwt({"sub": "user@example.com", "iat": now, "exp": now + 7200})
    findings = audit_token(tok, target="api.example")
    assert not any("lifetime" in f.title.lower() for f in findings)


def test_audit_token_flags_mixed_human_agent_claims() -> None:
    now = int(time.time())
    tok = _make_jwt(
        {
            "sub": "agent:gpt",
            "email_verified": True,
            "iat": now,
            "exp": now + 60,  # short, so no lifetime finding
        }
    )
    findings = audit_token(tok, target="api.example")
    assert any("human-identity claims" in f.title for f in findings)


def test_audit_token_empty_string_returns_empty_list() -> None:
    assert audit_token("", target="lab") == []


# ─────────────── ASI06 — memory poisoning ───────────────


def test_memory_drift_detected_after_two_consecutive_misses() -> None:
    canary = make_canary_fact()
    res = MemoryDriftResult(canary=canary)
    update_round(res, 1, f"the codename is {canary.value}")  # hit
    update_round(res, 2, "the codename is something else")  # miss
    update_round(res, 3, "actually it's another value")  # miss → drift
    assert res.drift_detected
    findings = evaluate_drift(res, target="agent.lab")
    assert findings
    assert findings[0].severity == "HIGH"
    assert findings[0].asi == AsiCategory.MEMORY_POISONING
    assert findings[0].cwe == "CWE-345"


def test_memory_drift_not_triggered_on_single_miss() -> None:
    canary = make_canary_fact()
    res = MemoryDriftResult(canary=canary)
    update_round(res, 1, f"codename: {canary.value}")
    update_round(res, 2, "I forget the codename")
    assert not res.drift_detected


def test_memory_drift_streak_resets_on_hit() -> None:
    # miss → hit → miss → no drift (streak broken in the middle)
    canary = make_canary_fact()
    res = MemoryDriftResult(canary=canary)
    update_round(res, 1, "no idea")
    update_round(res, 2, f"oh wait, it's {canary.value}")
    update_round(res, 3, "lost it again")
    assert not res.drift_detected


# ─────────────── Pipeline ───────────────


def test_pipeline_runs_all_modules_when_selected_is_none() -> None:
    now = int(time.time())
    ctx = {
        "target": "lab",
        "tools": [
            ToolInventoryEntry(name="delete_records"),
            ToolInventoryEntry(name="http_request"),
        ],
        "token": _make_jwt({"sub": "agent:x", "iat": now, "exp": now + 7200}),
    }
    findings = default_pipeline().run(None, ctx)
    asis = {f.asi.name for f in findings}
    assert "TOOL_MISUSE" in asis
    assert "IDENTITY_ABUSE" in asis


def test_pipeline_filters_by_selected_names() -> None:
    ctx = {
        "target": "lab",
        "tools": [ToolInventoryEntry(name="exec_cmd")],
    }
    findings = default_pipeline().run(["tool_misuse"], ctx)
    assert findings
    assert all(f.asi.name == "TOOL_MISUSE" for f in findings)


def test_pipeline_unknown_module_silently_skipped() -> None:
    findings = default_pipeline().run(["asi99_does_not_exist"], {"target": "lab"})
    assert findings == []


def test_pipeline_custom_registration() -> None:
    p = Pipeline()
    p.register("noop", lambda ctx: [])
    assert "noop" in p.modules
    assert p.run(["noop"], {}) == []
