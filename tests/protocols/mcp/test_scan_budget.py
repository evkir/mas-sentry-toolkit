# SPDX-License-Identifier: AGPL-3.0-or-later
"""The scan has to stop, and stopping has to be reported as a hole in coverage."""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from mas_sentry.protocols.mcp import client as client_mod
from mas_sentry.protocols.mcp.client import (
    BUDGET_EXHAUSTED,
    DISCOVER_METHOD,
    META_SERVER_INFO,
    McpClient,
    ScanBudget,
)
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse
from mas_sentry.protocols.mcp.runtime import _run_all_checks

TOOL_COUNT = 3

_DISCOVER = {
    "result": {
        "capabilities": {"tools": {}},
        "resultType": "complete",
        "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
    }
}

_TOOLS = {
    "result": {
        "tools": [
            {
                "name": f"fetch_{i}",
                "description": "fetch a url",
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"type": "string"}, "path": {"type": "string"}},
                },
            }
            for i in range(TOOL_COUNT)
        ]
    }
}


class _Transport:
    """Counts what actually went out, which is the only proof a budget bit."""

    def __init__(self) -> None:
        self.sent: list[str] = []
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        method = body["method"]
        self.sent.append(method)
        if method == DISCOVER_METHOD:
            return JsonRpcResponse(id=body.get("id"), result=_DISCOVER["result"])
        if method == "tools/list":
            return JsonRpcResponse(id=body.get("id"), result=_TOOLS["result"])
        if method == "tools/call":
            return JsonRpcResponse(id=body.get("id"), result={"content": [{"type": "text", "text": "ok"}]})
        if method in ("resources/list", "resources/templates/list", "prompts/list"):
            key = {
                "resources/list": "resources",
                "resources/templates/list": "resourceTemplates",
                "prompts/list": "prompts",
            }[method]
            return JsonRpcResponse(id=body.get("id"), result={key: []})
        return JsonRpcResponse(id=body.get("id"), error={"code": -32601, "message": "Method not found"})

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


@pytest.fixture()
def ticking(monkeypatch: pytest.MonkeyPatch):
    """One second of budget per clock read, so the tests do not race a real clock.

    Only `elapsed` is controllable this way: the dataclass binds
    `default_factory=_now` at definition, so every budget here states its own
    `started` instead of hoping the patch reaches the constructor.
    """
    counter = itertools.count()
    monkeypatch.setattr(client_mod, "_now", lambda: float(next(counter)))


def test_a_budget_latches_once_it_is_gone(ticking: None) -> None:
    # The clock reads 0, 1, 2, ... one tick per spend, so three fit inside a
    # budget of three seconds and the fourth is the one that finds it gone.
    budget = ScanBudget(seconds=3.0, started=0.0)
    assert budget.spend("tools/list") is True
    assert budget.spend("tools/list") is True
    assert budget.spend("resources/list") is True
    assert budget.spend("tools/call") is False
    assert budget.exhausted is True
    assert budget.stopped_at == "tools/call"
    # Still false afterwards, and the place it stopped is not overwritten.
    assert budget.spend("resources/read") is False
    assert budget.stopped_at == "tools/call"


def test_only_requests_that_went_out_are_counted(ticking: None) -> None:
    budget = ScanBudget(seconds=3.0, started=0.0)
    for method in ("a", "b", "c", "d", "e"):
        budget.spend(method)
    assert budget.requests == 3, "a refused request must not be counted as one that was sent"


def test_a_spent_budget_stops_the_request_reaching_the_wire(ticking: None) -> None:
    transport = _Transport()
    budget = ScanBudget(seconds=1.0, started=0.0)
    client = McpClient(transport, budget=budget)
    budget.spend("tools/list")
    resp = client.send("tools/call", {"name": "fetch_0", "arguments": {}})
    assert transport.sent == [], "a request was issued after the budget was spent"
    assert resp.error is not None
    assert resp.error["code"] == BUDGET_EXHAUSTED
    assert "scanner bound" in resp.error["message"]


def test_the_refusal_is_ours_and_not_a_protocol_error(ticking: None) -> None:
    budget = ScanBudget(seconds=0.0, started=0.0)
    client = McpClient(_Transport(), budget=budget)
    resp = client.send("tools/list")
    assert resp.error is not None
    assert resp.error["code"] < -32768, "must sit outside the JSON-RPC reserved band"


def test_a_scan_that_ran_out_says_what_it_did_not_do(ticking: None) -> None:
    """The row exists, once, and names the modules that never ran."""
    client = McpClient(_Transport(), budget=ScanBudget(seconds=20.0, started=0.0))
    rows = _run_all_checks(client, transport="http", checks="all")
    stopped = [r for r in rows if r["check"] == "scan_budget_exhausted"]
    assert len(stopped) == 1
    detail = stopped[0]["detail"]
    assert stopped[0]["severity"] == "MEDIUM"
    assert "Modules not run:" in detail
    assert "traversal" in detail, "a module that never ran has to be named"
    assert "not absent" in detail


def test_the_row_says_how_much_of_the_inventory_was_reached(ticking: None) -> None:
    client = McpClient(_Transport(), budget=ScanBudget(seconds=20.0, started=0.0))
    rows = _run_all_checks(client, transport="http", checks="all")
    detail = next(r for r in rows if r["check"] == "scan_budget_exhausted")["detail"]
    assert f"of {TOOL_COUNT} tools" in detail


def test_findings_already_collected_survive_the_stop(ticking: None) -> None:
    """Stopping must not discard the scan; the fingerprint was earned before it."""
    client = McpClient(_Transport(), budget=ScanBudget(seconds=20.0, started=0.0))
    rows = _run_all_checks(client, transport="http", checks="all")
    assert any(r["check"] == "fingerprint" for r in rows)


def test_a_stop_during_enumeration_is_not_filed_against_the_surface(ticking: None) -> None:
    """One row, not one per listing the budget happened to refuse."""
    client = McpClient(_Transport(), budget=ScanBudget(seconds=20.0, started=0.0))
    rows = _run_all_checks(client, transport="http", checks="all")
    gaps = [r for r in rows if r["check"] == "enumeration_gap"]
    assert gaps == [], f"our own stop was reported as the target refusing to enumerate: {gaps}"
    assert len([r for r in rows if r["check"] == "scan_budget_exhausted"]) == 1


def test_a_scan_inside_its_budget_emits_no_row() -> None:
    """Pinned in both directions: a bound that always fires is not a bound."""
    client = McpClient(_Transport(), budget=ScanBudget(seconds=3600.0))
    rows = _run_all_checks(client, transport="http", checks="all")
    assert [r for r in rows if r["check"] == "scan_budget_exhausted"] == []


def test_a_client_without_a_budget_behaves_as_before() -> None:
    transport = _Transport()
    client = McpClient(transport)
    rows = _run_all_checks(client, transport="http", checks="all")
    assert [r for r in rows if r["check"] == "scan_budget_exhausted"] == []
    assert transport.sent, "an unbudgeted scan still has to run"
