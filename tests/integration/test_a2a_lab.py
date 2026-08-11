# SPDX-License-Identifier: AGPL-3.0-or-later
"""Passive A2A scan against the live lab agent built on the reference SDK.

Every other A2A test in this repo drives the client through
httpx.MockTransport, which validates MAS-Sentry against MAS-Sentry's own
idea of the wire. This module spawns the real `a2a-sdk` server from
lab/a2a/agent.py and scans it over a real socket, so a divergence between
what we emit and what the reference implementation accepts shows up as a
test failure rather than as a silent false negative in the field.

Skipped when the optional lab dependencies are absent (pip install -e '.[lab]').
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("a2a", reason="a2a-sdk not installed - pip install -e '.[lab]'")
pytest.importorskip("uvicorn", reason="uvicorn not installed - pip install -e '.[lab]'")

REPO_ROOT = Path(__file__).resolve().parents[2]
STARTUP_TIMEOUT_S = 30.0
POLL_INTERVAL_S = 0.25


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
        return port


def _wait_for_port(port: int, deadline_s: float = STARTUP_TIMEOUT_S) -> bool:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(POLL_INTERVAL_S)
    return False


def _spawn_agent(extra_env: dict[str, str] | None = None) -> Iterator[str]:
    """Spawn the lab A2A agent and yield its base URL."""
    port = _free_port()
    env = {
        "A2A_LAB_HOST": "127.0.0.1",
        "A2A_LAB_PORT": str(port),
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(REPO_ROOT),
    }
    env.update(extra_env or {})
    proc = subprocess.Popen(
        [sys.executable, "-m", "lab.a2a.agent"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        if not _wait_for_port(port):
            proc.terminate()
            out = proc.communicate(timeout=10)[0]
            pytest.fail(f"lab A2A agent did not come up on {port}: {out!r}")
        yield f"http://127.0.0.1:{port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="module")
def lab_agent() -> Iterator[str]:
    """The default agent: strict v1.0, replying with a Task."""
    yield from _spawn_agent()


@pytest.fixture(scope="module")
def status_reply_agent() -> Iterator[str]:
    """An agent whose whole reply rides on the task's status message.

    Artifacts stay empty. This is the reference JS server's default shape
    and the one an artifact-only scan silently reports as an agent that
    said nothing at all.
    """
    yield from _spawn_agent({"A2A_LAB_REPLY": "status"})


@pytest.fixture(scope="module")
def inline_reply_agent() -> Iterator[str]:
    """An agent answering in one turn with a Message and no Task.

    This is spec-legal - SendMessageResponse is a oneof - and it is the shape
    a scanner reading only artifacts cannot see.
    """
    yield from _spawn_agent({"A2A_LAB_REPLY": "message"})


def _titles(findings: list) -> set[str]:
    return {f.title for f in findings}


def test_discovery_reads_the_v1_well_known_card(lab_agent: str) -> None:
    """The v1.0 well-known path and card shape are read without a fallback."""
    from mas_sentry.protocols.a2a.client import A2AClient

    with A2AClient(lab_agent) as client:
        card = client.discover()
    assert card.name == "vuln-a2a-lab"
    assert card.raw["supportedInterfaces"][0]["protocolBinding"] == "JSONRPC"


def test_endpoint_resolves_from_supported_interfaces(lab_agent: str) -> None:
    """The JSON-RPC endpoint comes from the card, not from the base URL."""
    from mas_sentry.protocols.a2a.client import A2AClient

    with A2AClient(lab_agent) as client:
        client.discover()
        assert client._rpc_endpoint() == f"{lab_agent}/a2a/v1"


def test_passive_scan_flags_the_weak_card(lab_agent: str, tmp_path: Path) -> None:
    """The passive scan raises every finding the lab card is built to trigger."""
    from mas_sentry.protocols.a2a.runtime import run_a2a_scan

    findings = run_a2a_scan(
        target=lab_agent,
        out=tmp_path / "a2a.json",
        scope_confirmed=False,
        active=False,
    )
    titles = _titles(findings)
    assert "AgentCard enforces no authentication requirement" in titles
    assert "OAuth2 scheme advertises a wildcard scope" in titles
    assert "OAuth2 scheme advertises an admin-family scope" in titles
    assert "AgentCard is not signed" in titles
    assert "AgentCard endpoint served over cleartext HTTP" in titles
    assert any(t.startswith("Agent Card Poisoning") for t in titles)
    assert any(t.startswith("Agent Card routing-hijack") for t in titles)


def test_passive_scan_writes_findings_to_disk(lab_agent: str, tmp_path: Path) -> None:
    """Findings reach the on-disk JSON that feeds `report convert`."""
    import json

    from mas_sentry.protocols.a2a.runtime import run_a2a_scan

    out = tmp_path / "nested" / "a2a.json"
    findings = run_a2a_scan(target=lab_agent, out=out, scope_confirmed=False, active=False)
    payload = json.loads(out.read_text())
    assert len(payload["findings"]) == len(findings)


# --- Active probing: pinned defects ---------------------------------------
#
# These encode the behaviour the active scan is supposed to have. They fail
# today, which is the point: the probes cannot complete a single JSON-RPC
# call against a reference v1.0 server, and the scan reports that as a clean
# result instead of as an error. strict=True means each one starts failing
# the suite the moment it is fixed but not un-marked.

_PROBE_MODULES = {
    "a2a.probe.task-id-collision",
    "a2a.probe.unauthorized-cancel",
    "a2a.probe.indirect-injection",
}


def _active_findings(target: str, out: Path) -> list:
    from mas_sentry.protocols.a2a.runtime import run_a2a_scan

    return run_a2a_scan(target=target, out=out, scope_confirmed=False, active=True)


def test_active_scan_runs_every_probe(lab_agent: str, tmp_path: Path) -> None:
    """All three active probes must reach the endpoint and report."""
    findings = _active_findings(lab_agent, tmp_path / "a2a.json")
    modules = {f.module for f in findings if f.module.startswith("a2a.probe.")}
    assert modules == _PROBE_MODULES


def test_echoed_canary_is_flagged(lab_agent: str, tmp_path: Path) -> None:
    """The lab agent echoes the payload, so the canary probe must flag it."""
    findings = _active_findings(lab_agent, tmp_path / "a2a.json")
    injection = [f for f in findings if f.module == "a2a.probe.indirect-injection"]
    assert injection, "indirect-injection probe produced no finding"
    assert injection[0].severity.value != "INFO"


def test_cancel_probe_records_the_rpc_error_code(lab_agent: str, tmp_path: Path) -> None:
    """A rejection verdict must name the JSON-RPC code it was drawn from.

    Without the code an operator cannot tell an authorization control
    ("task not found") from an endpoint that never implemented the method
    at all - the second is not evidence of anything.
    """
    import re

    findings = _active_findings(lab_agent, tmp_path / "a2a.json")
    cancel = [f for f in findings if f.module == "a2a.probe.unauthorized-cancel"]
    assert cancel, "unauthorized-cancel probe produced no finding"
    assert re.search(r"-3\d{4}", cancel[0].detail), cancel[0].detail


def test_canary_is_found_when_the_agent_replies_with_a_message(inline_reply_agent: str, tmp_path: Path) -> None:
    """An agent that never creates a Task must still be caught echoing."""
    findings = _active_findings(inline_reply_agent, tmp_path / "a2a.json")
    injection = [f for f in findings if f.module == "a2a.probe.indirect-injection"]
    assert injection, "indirect-injection probe produced no finding"
    assert injection[0].severity.value != "INFO"
    assert "could not run" not in injection[0].title


def test_canary_is_found_when_the_agent_replies_on_the_task_status(status_reply_agent: str, tmp_path: Path) -> None:
    """An agent answering with no artifacts must still be caught echoing."""
    findings = _active_findings(status_reply_agent, tmp_path / "a2a.json")
    injection = [f for f in findings if f.module == "a2a.probe.indirect-injection"]
    assert injection, "indirect-injection probe produced no finding"
    assert injection[0].severity.value != "INFO"
    assert "could not run" not in injection[0].title
