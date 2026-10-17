# SPDX-License-Identifier: AGPL-3.0-or-later
"""The authorization chain, against a server built on the reference SDK's routes.

A hand-written 401 fixture proves the parser reads what its author wrote. This
module spawns lab/mcp/auth_server.py, whose metadata documents and well-known
paths come from `mcp.server.auth.routes`, so the shape MST reads is the shape a
conforming server serves.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed - pip install -e '.[lab]'")
pytest.importorskip("uvicorn", reason="uvicorn not installed - pip install -e '.[lab]'")

REPO_ROOT = Path(__file__).resolve().parents[2]
STARTUP_TIMEOUT_S = 30.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _wait_for_port(port: int) -> bool:
    deadline = time.monotonic() + STARTUP_TIMEOUT_S
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.25)
    return False


def _spawn(break_mode: str = "") -> Iterator[int]:
    port = _free_port()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": str(REPO_ROOT),
        "MAS_SENTRY_AUTH_PORT": str(port),
        "MAS_SENTRY_AUTH_BREAK": break_mode,
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "lab.mcp.auth_server"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not _wait_for_port(port):
            pytest.fail(f"auth rig did not bind {port}")
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(scope="module")
def rig() -> Iterator[int]:
    yield from _spawn()


@pytest.fixture()
def silent_rig() -> Iterator[int]:
    yield from _spawn("challenge")


def _challenge(port: int):
    from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec
    from mas_sentry.protocols.mcp.transport_http import HttpConfig, StreamableHttpTransport

    transport = StreamableHttpTransport(HttpConfig(url=f"http://127.0.0.1:{port}/mcp"))
    transport.open()
    try:
        transport.send(JsonRpcCodec.request("server/discover", {}, req_id=1))
        return transport.auth_challenge
    finally:
        transport.close()


def test_the_pointer_survives_a_real_refusal(rig: int) -> None:
    challenge = _challenge(rig)
    assert challenge is not None
    assert challenge.status == 401
    assert challenge.scheme == "Bearer"
    assert challenge.resource_metadata == (f"http://127.0.0.1:{rig}/.well-known/oauth-protected-resource/mcp")


def test_a_refusal_without_a_header_records_nothing(silent_rig: int) -> None:
    """Pinned in both directions: the capture must not invent a challenge."""
    assert _challenge(silent_rig) is None


@pytest.mark.xfail(strict=True, reason="the codec admits a non-object error; the fix lands in the next commit")
def test_a_scan_survives_an_oauth_guarded_target(rig: int) -> None:
    """A target behind OAuth must end the scan as a handshake failure, not a crash.

    The assertion sits on `McpClient.connect()` rather than on `transport.send()`
    because that is where the scan actually reads the error: the transport hands
    the response back intact, and the first consumer to treat `error` as the
    object its type promises is the client. A test one layer below the defect is
    the R-2.3 trap - the covered function was never the one that breaks.

    `HandshakeFailed` is the right end state, not an improvement on it: the
    runtime catches that class and writes the gap row, so a refusal the scanner
    cannot get past still reaches `report convert` as a reason.
    """
    from mas_sentry.protocols.mcp.client import McpClient
    from mas_sentry.protocols.mcp.errors import HandshakeFailed
    from mas_sentry.protocols.mcp.transport_http import HttpConfig, open_http

    with pytest.raises(HandshakeFailed), open_http(HttpConfig(url=f"http://127.0.0.1:{rig}/mcp")) as transport:
        McpClient(transport).connect()


@pytest.mark.xfail(strict=True, reason="the codec admits a non-object error; the fix lands in the next commit")
def test_the_cli_writes_a_report_against_an_oauth_guarded_target(rig: int, tmp_path: Path) -> None:
    """The whole point of NS-1: a scan that could not happen still leaves a file.

    Driven through the CLI because that is the contract an operator and a
    pipeline depend on - `mcp scan | report convert` breaks on a missing file,
    and a traceback is not a report.
    """
    from typer.testing import CliRunner

    from mas_sentry.cli import app

    out = tmp_path / "scan.json"
    CliRunner().invoke(
        app,
        ["mcp", "scan", "-t", f"http://127.0.0.1:{rig}/mcp", "--confirm-scope", "-o", str(out)],
    )
    assert out.exists()
    rows = json.loads(out.read_text())
    assert rows, "a scan that did not happen must still say so"


def test_an_oauth_error_body_does_not_crash_the_scan(rig: int) -> None:
    """RFC 6750 answers with a string `error`, which used to hit `.get` and abort."""
    from mas_sentry.protocols.mcp.jsonrpc import JsonRpcCodec
    from mas_sentry.protocols.mcp.transport_http import HttpConfig, StreamableHttpTransport

    transport = StreamableHttpTransport(HttpConfig(url=f"http://127.0.0.1:{rig}/mcp"))
    transport.open()
    try:
        resp = transport.send(JsonRpcCodec.request("server/discover", {}, req_id=1))
    finally:
        transport.close()
    assert resp.is_error
