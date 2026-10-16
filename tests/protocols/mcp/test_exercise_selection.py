# SPDX-License-Identifier: AGPL-3.0-or-later
"""Which tools a scan may call on a target it knows nothing about.

`exercise_tools` calls tools on purpose: a server that rewrites a descriptor on
first use moves nothing until something uses it, and opening that window is the
only way the mutation audit has anything to compare. What this module pins is
which tools may be called to open it.

The selection is a test on the tool's name, and a name test can be wrong in two
directions. Wrong towards silence costs coverage: a swap keyed to a tool MST
declined to call goes unseen. Wrong towards noise costs the target: the scan
runs an operation on a live server, which is the same event MST reports as a
finding when a server does it to a model (R-7.6).

Only the first of those is recoverable, which is what decides the polarity. The
corpus below is every name needed to show the current polarity is the other one:
each passes the mutating-verb blocklist today - measured against the predicate,
not imagined - because a blocklist enumerates what to refuse, and a destructive
verb nobody thought to enumerate is allowed through by default.
"""

from __future__ import annotations

from typing import Any

from mas_sentry.protocols.mcp.audit.tool_mutation import exercise_tools
from mas_sentry.protocols.mcp.client import DISCOVER_METHOD, META_SERVER_INFO, McpClient
from mas_sentry.protocols.mcp.jsonrpc import JsonRpcResponse

_DISCOVER = {
    "capabilities": {"tools": {}},
    "cacheScope": "private",
    "resultType": "complete",
    "ttlMs": 0,
    "_meta": {META_SERVER_INFO: {"name": "rig", "version": "1.0"}},
}

# Names a real deployment would carry, each of which the scan calls today. They
# are not edge cases: `overwrite_file` is refused only if "overwrite" was
# enumerated, since "write" is a different word, and `charge_card` names an
# irreversible operation with no verb a blocklist author would reach for.
_DESTRUCTIVE = (
    "wipe_disk",
    "terminate_pod",
    "revoke_token",
    "overwrite_file",
    "charge_card",
    "sweep_cluster",
)

# The other half of R-2.4. A selection that refuses everything would pass the
# assertion above and silently end the mutation audit, because a swap keyed to
# first use never fires.
_READ_SHAPED = ("get_status", "list_items", "search_notes", "read_file")

_STRING_PARAM: dict[str, Any] = {
    "type": "object",
    "properties": {"subject": {"type": "string"}},
    "required": ["subject"],
}


class _Transport:
    """Answers enough to enumerate, and records every call that reaches it."""

    def __init__(self, names: tuple[str, ...], hints: dict[str, bool] | None = None) -> None:
        self.names = names
        self.hints = hints or {}
        self.called: list[str] = []
        self.emit_routing_headers = False
        self.protocol_version: str | None = None
        self.supports_headers = False
        self.notifications: list[dict[str, Any]] = []

    def send(self, req: Any) -> JsonRpcResponse:
        body = req.to_dict()
        method = body["method"]
        if method == DISCOVER_METHOD:
            return JsonRpcResponse(id=body.get("id"), result=_DISCOVER)
        if method == "tools/list":
            tools: list[dict[str, Any]] = []
            for n in self.names:
                tool: dict[str, Any] = {"name": n, "description": n, "inputSchema": _STRING_PARAM}
                if n in self.hints:
                    tool["annotations"] = {"readOnlyHint": self.hints[n]}
                tools.append(tool)
            return JsonRpcResponse(id=body.get("id"), result={"tools": tools})
        if method == "tools/call":
            name = (body.get("params") or {}).get("name")
            self.called.append(str(name))
        return JsonRpcResponse(id=body.get("id"), result={})

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        return self.send(req)


def _rig(names: tuple[str, ...], hints: dict[str, bool] | None = None) -> tuple[McpClient, _Transport]:
    transport = _Transport(names, hints)
    client = McpClient(transport)
    client.connect()
    return client, transport


def test_a_scan_executes_nothing_it_was_not_able_to_recognise() -> None:
    """Measured on the wire rather than on the return value.

    `exercise_tools` reports which tools it decided to call; what the target
    experienced is which requests arrived. Those are the same number until the
    day they are not, and the claim here is about the target.
    """
    client, transport = _rig(_DESTRUCTIVE)
    exercise_tools(client)
    assert transport.called == []


def test_a_read_shaped_tool_is_still_called() -> None:
    """Not a proof of the fix - a bound on it, and green either way by design.

    Without this, the cheapest way to pass the assertion above is to call
    nothing at all, which would close the window the mutation audit measures
    across and turn every rug pull into a clean report (R-2.1).
    """
    client, transport = _rig(_READ_SHAPED)
    exercise_tools(client)
    assert transport.called == list(_READ_SHAPED)


def test_a_declared_write_is_refused_under_a_retrieval_verb() -> None:
    """The name says retrieval and the target says otherwise; the target wins.

    A hint is only ever read in this direction. The symmetric case below is
    what the asymmetry is for.
    """
    client, transport = _rig(("get_quote",), hints={"get_quote": False})
    exercise_tools(client)
    assert transport.called == []


def test_a_declared_read_does_not_make_a_tool_callable() -> None:
    """A server asking to be called is not a reason to call it (R-2.4).

    Without this the selection would be the target's to set: `readOnlyHint`
    is a value the server chooses, and the server is the thing under test.
    """
    client, transport = _rig(("charge_card",), hints={"charge_card": True})
    exercise_tools(client)
    assert transport.called == []
