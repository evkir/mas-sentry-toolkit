# SPDX-License-Identifier: AGPL-3.0-or-later
"""An authorization boundary that admits a caller it should have refused.

Source: CVE-2026-59822 (`litellm` < 1.84.0, GHSA-7488-6r32-c95q), the first MCP
defect on CISA's Known Exploited Vulnerabilities catalog. The rig reproduces the
1.83.9 gate branch for branch; see `lab/mcp/gate_server.py` for the reading of
the published package.

Every assertion here runs through the CLI. The defect class is about which
session a target grants, so the thing under test is what a scan reports, not
what a function returns - and the two have already come apart twice in this
subsystem (R-2.3).

Each case also asserts the marker file is absent. Establishing that a session is
reachable takes `initialize` and `tools/list`; it never takes a `tools/call`, so
no tool body may run (R-7.6). The rig's only tool writes that file when its body
executes, which is what holds the claim to the disk rather than to a comment.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
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


@pytest.fixture()
def gate(tmp_path: Path) -> Iterator[Callable[[str], tuple[int, Path]]]:
    """Start the rig in one mode and hand back its port and marker path."""
    started: list[subprocess.Popen[bytes]] = []

    def run(mode: str) -> tuple[int, Path]:
        port = _free_port()
        marker = tmp_path / f"marker-{mode}"
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONPATH": str(REPO_ROOT),
            "MAS_SENTRY_GATE_MODE": mode,
            "MAS_SENTRY_GATE_PORT": str(port),
            "MAS_SENTRY_GATE_MARKER": str(marker),
        }
        proc = subprocess.Popen(
            [sys.executable, "-m", "lab.mcp.gate_server"],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        started.append(proc)
        if not _wait_for_port(port):
            pytest.fail(f"gate rig did not bind {port} in mode {mode}")
        return port, marker

    try:
        yield run
    finally:
        for proc in started:
            proc.terminate()
            proc.wait(timeout=10)


def _scan(port: int, out: Path) -> list[dict[str, object]]:
    from typer.testing import CliRunner

    from mas_sentry.cli import app

    CliRunner().invoke(
        app,
        ["mcp", "scan", "-t", f"http://127.0.0.1:{port}/mcp", "--confirm-scope", "-o", str(out)],
    )
    assert out.exists(), "a scan always leaves a report"
    rows: list[dict[str, object]] = json.loads(out.read_text())
    return rows


_BYPASS_REASON = "the bypass probe does not exist yet; the detector lands in the next commit"


@pytest.mark.xfail(strict=True, reason=_BYPASS_REASON)
def test_any_bearer_value_opens_a_session(gate: Callable[[str], tuple[int, Path]], tmp_path: Path) -> None:
    """Branch 3 of the 1.83.9 gate: key validation fails and the fallback admits anyway.

    Two generated tokens rather than one. A single token that worked could have
    been a real key by accident; two that work the same way cannot both be, and
    a target answering them differently is telling us something this probe
    cannot read.
    """
    port, marker = gate("bearer-any")
    rows = _scan(port, tmp_path / "scan.json")
    found = [r for r in rows if r["check"] == "auth_bypass"]
    assert found, f"a boundary that admits any token is the finding; got {sorted({str(r['check']) for r in rows})}"
    assert found[0]["severity"] == "HIGH"
    assert not marker.exists(), "reachability was established without executing a tool body (R-7.6)"


@pytest.mark.xfail(strict=True, reason=_BYPASS_REASON)
def test_a_public_route_marker_opens_a_session(gate: Callable[[str], tuple[int, Path]], tmp_path: Path) -> None:
    """Branch 1 of the same gate: the public-route test matched a substring of the URL.

    The query form is the only one of the three vectors 1.84.0 names that keeps
    every other variable fixed - same path, same method, same headers.
    """
    port, marker = gate("public-marker")
    rows = _scan(port, tmp_path / "scan.json")
    found = [r for r in rows if r["check"] == "auth_bypass"]
    assert found, f"a route marker that bypasses auth is the finding; got {sorted({str(r['check']) for r in rows})}"
    assert found[0]["severity"] == "HIGH"
    assert not marker.exists(), "reachability was established without executing a tool body (R-7.6)"


@pytest.mark.xfail(strict=True, reason=_BYPASS_REASON)
def test_a_boundary_that_holds_is_reported_as_holding(gate: Callable[[str], tuple[int, Path]], tmp_path: Path) -> None:
    """The fixed shape, which has to produce a row rather than silence (R-7.5).

    A probe that found nothing and said nothing is indistinguishable from a
    probe that never ran, and the operator cannot tell which they got.
    """
    port, marker = gate("strict")
    rows = _scan(port, tmp_path / "scan.json")
    checks = {str(r["check"]) for r in rows}
    assert "auth_bypass" not in checks, "the fixed gate must not produce a finding (R-2.4)"
    assert "auth_bypass_unverified" in checks, f"the probe has to say it ran and found nothing; got {sorted(checks)}"
    assert not marker.exists(), "reachability was established without executing a tool body (R-7.6)"


def test_a_server_without_a_boundary_is_not_a_bypass(gate: Callable[[str], tuple[int, Path]], tmp_path: Path) -> None:
    """The other half of R-2.4, green before the detector and after it.

    A local server that asks for nothing is a legitimate deployment, not a
    bypassed boundary. There is no boundary to bypass, the handshake succeeds,
    and the scan proceeds as an ordinary scan - so neither key may appear.
    """
    port, _ = gate("open")
    rows = _scan(port, tmp_path / "scan.json")
    checks = {str(r["check"]) for r in rows}
    assert "auth_bypass" not in checks
    assert "auth_bypass_unverified" not in checks
    assert "fingerprint" in checks, "an open server is scanned, not bounded"
