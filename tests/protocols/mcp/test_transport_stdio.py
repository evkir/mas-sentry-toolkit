# SPDX-License-Identifier: AGPL-3.0-or-later
"""STDIO reads are bounded, and a dead server says why.

A blocking read against a server the target controls is a denial of service on
the operator: the process that hangs is ours. These drive real subprocesses,
because the failure being tested is what the OS does with a pipe, which no
in-process stub reproduces.
"""

from __future__ import annotations

import json
import sys
import time

import pytest

from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec
from mas_sentry.protocols.mcp.transport_stdio import StdioConfig, open_stdio

TIMEOUT_S = 1.0
# Generous: the assertion is "bounded", not "fast".
MAX_WAIT_S = 10.0

_SILENT = "import sys; sys.stdin.readline(); import time; time.sleep(60)"
_CRASHER = "import sys; sys.stderr.write('boom: bad config\\n'); sys.exit(3)"
_LOUD = (
    "import sys, json;"
    "sys.stdin.readline();"
    "big = [{'name': 'tool%d' % i, 'description': 'x' * 500} for i in range(400)];"
    "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': {'tools': big}}) + chr(10));"
    "sys.stdout.flush();"
    "import time; time.sleep(30)"
)


def _config(script: str) -> StdioConfig:
    return StdioConfig(command=[sys.executable, "-c", script], timeout=TIMEOUT_S)


def test_a_silent_server_times_out_instead_of_hanging() -> None:
    """The whole defect: this test used to never finish."""
    with open_stdio(_config(_SILENT)) as transport:
        started = time.monotonic()
        resp = transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        elapsed = time.monotonic() - started

    assert elapsed < MAX_WAIT_S
    assert resp.is_error
    assert "within 1.0s" in str(resp.error)


def test_a_timeout_becomes_an_enumeration_gap() -> None:
    """A stall must be reported, not swallowed and not fatal."""
    from mas_sentry.protocols.mcp.client import McpClient

    with open_stdio(_config(_SILENT)) as transport:
        client = McpClient(transport)
        assert client.list_tools() == []

    issue = client.enumeration_issues[0]
    assert issue.method == "tools/list"
    assert issue.severity == "MEDIUM"
    assert "no response" in issue.detail


def test_a_dead_server_reports_its_exit_code_and_stderr() -> None:
    """A server that dies on startup is the most common stdio failure."""
    with open_stdio(_config(_CRASHER)) as transport:
        time.sleep(0.3)
        resp = transport.send(JsonRpcCodec.request("initialize", {}, req_id=1))

    message = str(resp.error)
    assert "exited with code 3" in message
    assert "bad config" in message


def test_a_response_larger_than_one_read_is_reassembled() -> None:
    """Framing is by newline, not by read boundary."""
    with open_stdio(_config(_LOUD)) as transport:
        resp = transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))

    assert not resp.is_error, resp.error
    assert len(json.loads(json.dumps(resp.result))["tools"]) == 400


@pytest.mark.parametrize("script", [_SILENT, _CRASHER])
def test_a_failed_read_leaves_the_transport_usable(script: str) -> None:
    """One dead call must not poison the next one."""
    with open_stdio(_config(script)) as transport:
        first = transport.send(JsonRpcCodec.request("tools/list", {}, req_id=1))
        second = transport.send(JsonRpcCodec.request("prompts/list", {}, req_id=2))

    assert first.is_error
    assert second.is_error
