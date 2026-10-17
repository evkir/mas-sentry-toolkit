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


@pytest.fixture()
def weak_rig() -> Iterator[int]:
    """A rig that refuses and then publishes metadata saying the wrong things."""
    yield from _spawn("weak")


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


@pytest.mark.xfail(
    strict=True, reason="the auth audit is unreachable past a refused handshake; the fix lands in the next commit"
)
def test_the_auth_audit_reaches_a_target_behind_oauth(weak_rig: int, tmp_path: Path) -> None:
    """The RFC 9728 audit must run against the one class of target it was written for.

    `_run_all_checks` opens with `fingerprint()`, which calls `connect()`, and a
    target behind OAuth refuses the handshake - so every module after it,
    including the authorization chain, was unreachable in the field. The module
    itself works: pointed at this rig by hand it returns three rows, one of them
    the HIGH for an issuer reachable over cleartext off loopback. None of them
    ever reached a report.

    Driven through the CLI because the defect is reachability, not logic. A unit
    test of `audit_protected_resource` passes today and says nothing about
    whether a scan ever calls it - the R-2.3 trap, in the same module twice.
    """
    from typer.testing import CliRunner

    from mas_sentry.cli import app

    out = tmp_path / "scan.json"
    CliRunner().invoke(
        app,
        ["mcp", "scan", "-t", f"http://127.0.0.1:{weak_rig}/mcp", "--confirm-scope", "-o", str(out)],
    )
    assert out.exists()
    rows = json.loads(out.read_text())
    checks = {r["check"] for r in rows}

    assert "auth_required" in checks, "a declared boundary bounds the scan and has to be said"
    assert "auth_transport" in checks, "the HIGH the audit produces by hand must reach the report"
    high = [r for r in rows if r["check"] == "auth_transport"]
    assert high and high[0]["severity"] == "HIGH"


def test_an_unreachable_target_is_still_unreachable(tmp_path: Path) -> None:
    """The other half of R-2.4: a refusal at the auth boundary is not every refusal.

    Green before the fix and after it. A port with nothing behind it must keep
    producing the gap row, because a fix that read every failed handshake as an
    authenticated target would file this scanner's own blindness as a fact about
    whatever it was pointed at.
    """
    from typer.testing import CliRunner

    from mas_sentry.cli import app

    out = tmp_path / "scan.json"
    CliRunner().invoke(
        app,
        ["mcp", "scan", "-t", f"http://127.0.0.1:{_free_port()}/mcp", "--confirm-scope", "-o", str(out)],
    )
    assert out.exists()
    rows = json.loads(out.read_text())
    assert [r["check"] for r in rows] == ["target_unreachable"]


def test_the_pointer_survives_a_real_refusal(rig: int) -> None:
    challenge = _challenge(rig)
    assert challenge is not None
    assert challenge.status == 401
    assert challenge.scheme == "Bearer"
    assert challenge.resource_metadata == (f"http://127.0.0.1:{rig}/.well-known/oauth-protected-resource/mcp")


def test_a_refusal_without_a_header_records_nothing(silent_rig: int) -> None:
    """Pinned in both directions: the capture must not invent a challenge."""
    assert _challenge(silent_rig) is None


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
