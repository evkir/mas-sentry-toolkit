# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI: `mas-sentry a2a scan` wiring, table render, scope + input handling."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.core.finding import Finding, Severity
from mas_sentry.core.scope import ScopeViolation
from mas_sentry.protocols.a2a import runtime as a2a_runtime

runner = CliRunner()


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            module="a2a.card_audit",
            title="AgentCard declares no authentication schemes",
            detail="Anyone can submit tasks to this agent",
            severity=Severity.HIGH,
            target="http://x.lab",
            tags=["a2a", "CWE-306"],
        ),
        Finding(
            module="a2a.probe.indirect-injection",
            title="indirect-injection: unsafe server behavior",
            detail="Canary present in artifacts",
            severity=Severity.CRITICAL,
            target="http://x.lab",
            tags=["a2a", "probe", "indirect-injection", "ASI01_Goal_Hijack"],
        ),
    ]


def test_a2a_scan_passive_renders_table(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake(**kwargs: object) -> list[Finding]:
        captured.update(kwargs)
        return _sample_findings()

    monkeypatch.setattr(a2a_runtime, "run_a2a_scan", _fake)
    result = runner.invoke(app, ["a2a", "scan", "--target", "http://x.lab"])
    assert result.exit_code == 0, result.output
    assert captured["active"] is False
    assert captured["scope_confirmed"] is False
    assert "A2A scan (passive)" in result.stdout
    assert "a2a.card_audit" in result.stdout
    assert "2 finding(s)" in result.stdout


def test_a2a_scan_active_flag_flows_through(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def _fake(**kwargs: object) -> list[Finding]:
        captured.update(kwargs)
        return []

    monkeypatch.setattr(a2a_runtime, "run_a2a_scan", _fake)
    result = runner.invoke(app, ["a2a", "scan", "-t", "http://x.lab", "--active", "--confirm-scope"])
    assert result.exit_code == 0, result.output
    assert captured["active"] is True
    assert captured["scope_confirmed"] is True
    assert "A2A scan (active)" in result.stdout


def test_a2a_scan_scope_violation_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake(**kwargs: object) -> list[Finding]:
        raise ScopeViolation("Target 'https://api.example.com' is outside the lab allowlist.")

    monkeypatch.setattr(a2a_runtime, "run_a2a_scan", _fake)
    result = runner.invoke(app, ["a2a", "scan", "-t", "https://api.example.com"])
    assert result.exit_code == 2


def test_a2a_scan_rejects_non_http_target() -> None:
    result = runner.invoke(app, ["a2a", "scan", "-t", "ftp://x.lab"])
    assert result.exit_code != 0


def test_a2a_registered_in_top_level_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "a2a" in result.output
