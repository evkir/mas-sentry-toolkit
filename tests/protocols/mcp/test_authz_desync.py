# SPDX-License-Identifier: AGPL-3.0-or-later
"""The authorization probe's outcomes other than a reachable tool.

The lab rig covers the two that need a real server: a filter on discovery only,
and the same filter on both levels. The rest are decisions the probe makes
before or instead of asking, and each of them is a case where the honest answer
is "this scan could not establish it" rather than silence (R-7.5).

The first is also a safety property, not a reporting one. A tool whose schema
requires nothing cannot be called in a way that fails validation, so the only
available call is one that would run it, and that call is never made (R-7.6).
A regression here would not produce a wrong row - it would execute a tool on
someone's cluster.
"""

from __future__ import annotations

from typing import Any

from mas_sentry.protocols.mcp.audit.authz_desync import (
    INCONCLUSIVE,
    REACHABLE,
    WITHDRAWN,
    probe_authz_desync,
)
from mas_sentry.protocols.mcp.audit.descriptor import BaselineEntry, build_tool_baseline
from mas_sentry.protocols.mcp.client import ToolDef
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse

_REQUIRED_SCHEMA = {"type": "object", "properties": {"namespace": {"type": "string"}}, "required": ["namespace"]}
_PERMISSIVE_SCHEMA = {"type": "object", "properties": {"namespace": {"type": "string"}}}


class _ScriptedTransport:
    """Answers each tools/call in order, and records what was asked."""

    def __init__(self, answers: list[dict[str, Any]]) -> None:
        self._answers = answers
        self.calls: list[dict[str, Any]] = []

    def send(self, request: Any) -> JsonRpcResponse:
        params = request.get("params", {}) if isinstance(request, dict) else {}
        self.calls.append(params)
        answer = self._answers.pop(0) if self._answers else {"result": {"content": []}}
        return JsonRpcResponse(id=1, result=answer.get("result"), error=answer.get("error"))


class _Client:
    def __init__(self, tools: list[ToolDef], answers: list[dict[str, Any]]) -> None:
        self._tools = tools
        self.transport = _ScriptedTransport(answers)

    def list_tools(self) -> list[ToolDef]:
        return self._tools

    def send(self, method: str, params: dict[str, Any] | None = None) -> JsonRpcResponse:
        return self.transport.send({"method": method, "params": params or {}})


def _error_body(text: str) -> dict[str, Any]:
    return {"result": {"content": [{"type": "text", "text": text}], "isError": True}}


def _baseline_with_withdrawn(schema: dict[str, Any]) -> dict[str, BaselineEntry]:
    """A baseline holding one advertised tool and one the target has withdrawn."""
    baseline = build_tool_baseline(
        [
            ToolDef(name="visible_echo", description="announced", input_schema=_REQUIRED_SCHEMA),
            ToolDef(name="sweep_cluster", description="withdrawn", input_schema=schema),
        ]
    )
    return baseline


def test_a_tool_requiring_nothing_is_never_called() -> None:
    """The safety case. No argument's absence is an error, so no call is safe."""
    client = _Client([ToolDef(name="visible_echo", description="a", input_schema=_REQUIRED_SCHEMA)], [])
    findings = probe_authz_desync(client, _baseline_with_withdrawn(_PERMISSIVE_SCHEMA))  # type: ignore[arg-type]

    assert [(f.outcome, f.reason) for f in findings] == [(INCONCLUSIVE, "schema-permits-empty-call")]
    assert client.transport.calls == [], "the probe must not call a tool it cannot call invalidly"


def test_a_target_with_no_reference_tool_says_so() -> None:
    """Without an announced tool to compare against, there is nothing to read."""
    client = _Client([ToolDef(name="ping", description="no arguments", input_schema={"type": "object"})], [])
    findings = probe_authz_desync(client, _baseline_with_withdrawn(_REQUIRED_SCHEMA))  # type: ignore[arg-type]

    reasons = [(f.outcome, f.reason) for f in findings]
    assert (INCONCLUSIVE, "no-reference-tool") in reasons
    assert client.transport.calls == [], "and no call is worth making"


def test_a_target_that_answers_everything_alike_is_inconclusive() -> None:
    """A target whose two references agree cannot be read differentially.

    Reported rather than resolved: guessing either way would be a verdict the
    answers do not support.
    """
    same = _error_body("error")
    client = _Client(
        [ToolDef(name="visible_echo", description="a", input_schema=_REQUIRED_SCHEMA)],
        [same, same, same],
    )
    findings = probe_authz_desync(client, _baseline_with_withdrawn(_REQUIRED_SCHEMA))  # type: ignore[arg-type]

    assert [(f.outcome, f.reason) for f in findings] == [(INCONCLUSIVE, "target-does-not-discriminate")]


def test_a_name_answered_as_unknown_is_not_a_finding() -> None:
    """The ordinary case: the tool really is gone, and the row says nothing else."""
    unknown = _error_body("Unknown tool: sweep_cluster")
    known = _error_body("Error executing tool visible_echo: 1 validation error for visible_echoArguments")
    client = _Client(
        [ToolDef(name="visible_echo", description="a", input_schema=_REQUIRED_SCHEMA)],
        [_error_body("Unknown tool: mst_absent_canary"), known, unknown],
    )
    findings = probe_authz_desync(client, _baseline_with_withdrawn(_REQUIRED_SCHEMA))  # type: ignore[arg-type]

    assert [(f.outcome, f.reason) for f in findings] == [(WITHDRAWN, "not-recognised")]


def test_a_name_answered_as_an_announced_tool_is_reachable() -> None:
    """The finding, driven offline so the criterion itself is pinned."""
    known = _error_body("Error executing tool visible_echo: 1 validation error for visible_echoArguments\nnamespace")
    target = _error_body("Error executing tool sweep_cluster: 1 validation error for sweep_clusterArguments\nnamespace")
    client = _Client(
        [ToolDef(name="visible_echo", description="a", input_schema=_REQUIRED_SCHEMA)],
        [_error_body("Unknown tool: mst_absent_canary"), known, target],
    )
    findings = probe_authz_desync(client, _baseline_with_withdrawn(_REQUIRED_SCHEMA))  # type: ignore[arg-type]

    assert [(f.outcome, f.reason) for f in findings] == [(REACHABLE, "answered-as-an-announced-tool")]
    finding = findings[0]
    assert finding.announced == "absent from tools/list"
    assert "<TOOL>" in finding.observed, "tool names are normalised out of both sides"
    assert "<TOOL>" in finding.reference_known_tool


def test_the_canary_name_is_fresh_on_every_run() -> None:
    """A fixed canary is a verdict about this scanner, which is the day-5 defect."""
    seen = set()
    for _ in range(3):
        client = _Client(
            [ToolDef(name="visible_echo", description="a", input_schema=_REQUIRED_SCHEMA)],
            [_error_body("x"), _error_body("y"), _error_body("z")],
        )
        probe_authz_desync(client, _baseline_with_withdrawn(_REQUIRED_SCHEMA))  # type: ignore[arg-type]
        seen.add(client.transport.calls[0]["name"])
    assert len(seen) == 3, "the name that cannot exist must be generated per scan"


def test_only_the_one_required_property_is_omitted() -> None:
    """The call is about one omission, not about every way it could be refused."""
    schema = {
        "type": "object",
        "properties": {"namespace": {"type": "string"}, "selector": {"type": "string"}},
        "required": ["namespace", "selector"],
    }
    client = _Client(
        [ToolDef(name="visible_echo", description="a", input_schema=_REQUIRED_SCHEMA)],
        [_error_body("x"), _error_body("y"), _error_body("z")],
    )
    probe_authz_desync(client, _baseline_with_withdrawn(schema))  # type: ignore[arg-type]

    target_call = client.transport.calls[-1]
    assert target_call["name"] == "sweep_cluster"
    assert target_call["arguments"] == {"selector": ""}, "every required property but the omitted one is sent"
