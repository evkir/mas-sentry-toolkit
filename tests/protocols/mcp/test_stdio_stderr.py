# SPDX-License-Identifier: AGPL-3.0-or-later
"""A server that logs must not be a server that hangs the scan."""

from __future__ import annotations

import sys
import textwrap

from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec
from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

# Comfortably past the 64 KiB a Linux pipe buffers, written before the server
# answers anything. Under the old transport this deadlocked: the child blocked
# on write, nothing on our side ever read, and stdout went quiet forever.
NOISY_SERVER = textwrap.dedent(
    """
    import json
    import sys

    for i in range(4000):
        print("x" * 60, file=sys.stderr)
    sys.stderr.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        print(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": {"ok": True}}), flush=True)
    """
)

DYING_SERVER = textwrap.dedent(
    """
    import sys
    print("ValueError: cannot read /etc/shadow", file=sys.stderr, flush=True)
    sys.exit(3)
    """
)


def _config(script: str) -> StdioConfig:
    return StdioConfig(command=[sys.executable, "-c", script], timeout=10.0)


def test_a_server_that_floods_stderr_still_answers() -> None:
    """The pipe fills at 64 KiB; a transport that never reads it stops the scan."""
    with open_stdio(_config(NOISY_SERVER)) as transport:
        resp = transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        assert resp.result == {"ok": True}
        second = transport.send(JsonRpcCodec.request("tools/list", {}, req_id=2))
        assert second.result == {"ok": True}


def test_the_reason_a_server_died_reaches_the_caller() -> None:
    """Read through the path a scan actually uses: the error a closed pipe returns."""
    with open_stdio(_config(DYING_SERVER)) as transport:
        resp = transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
    message = str((resp.error or {}).get("message", ""))
    assert "cannot read /etc/shadow" in message
    assert "exited with code 3" in message


def test_the_tail_is_not_consumed_by_reading_it() -> None:
    """Every later failure in the session needs the same context."""
    with open_stdio(_config(DYING_SERVER)) as transport:
        transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        first = list(transport.stderr_lines())
        second = list(transport.stderr_lines())
    assert first == second
    assert any("cannot read /etc/shadow" in line for line in first)
