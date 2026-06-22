# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI: abfp scan renders the per-agent graph-metrics table."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from mas_sentry.agents.abfp import runtime as abfp_runtime
from mas_sentry.agents.abfp.graph_metrics import AgentGraphMetrics
from mas_sentry.agents.abfp.runtime import AbfpScanResult
from mas_sentry.cli import app

runner = CliRunner()


def test_abfp_scan_renders_metrics_table(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = AbfpScanResult(
        findings=[],
        metrics={
            "robot_r1": AgentGraphMetrics(
                agent_id="robot_r1",
                pub_degree=3,
                sub_degree=1,
                betweenness=0.25,
                eigenvector=0.5,
                distinct_topics=4,
            )
        },
    )

    def _fake_scan(**kwargs: object) -> AbfpScanResult:
        return fake

    monkeypatch.setattr(abfp_runtime, "run_abfp_scan", _fake_scan)
    result = runner.invoke(app, ["abfp", "scan", "--target", "mqtt://127.0.0.1:1883", "--duration", "0"])
    assert result.exit_code == 0
    assert "Agent graph metrics" in result.stdout
    assert "robot_r1" in result.stdout


def test_abfp_scan_shows_finding_drivers(monkeypatch: pytest.MonkeyPatch) -> None:
    from mas_sentry.agents.abfp.rogue import RogueFinding
    from mas_sentry.agents.abfp.scoring import DimensionScore, compose

    score = compose("agent_a", [DimensionScore(name="identity", raw=0.6, reason="x")])
    finding = RogueFinding(
        agent_id="agent_a",
        score=score,
        diff_summary={"new_topics": [], "removed_topics": []},
        is_rogue=False,
    )
    fake = AbfpScanResult(findings=[finding], metrics={})

    monkeypatch.setattr(abfp_runtime, "run_abfp_scan", lambda **kwargs: fake)
    result = runner.invoke(app, ["abfp", "scan", "--target", "mqtt://127.0.0.1:1883", "--duration", "0"])
    assert result.exit_code == 0
    assert "agent_a" in result.stdout
    assert "identity" in result.stdout


def test_abfp_scan_emits_authorized_use_reminder_to_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = AbfpScanResult(findings=[], metrics={})
    monkeypatch.setattr(abfp_runtime, "run_abfp_scan", lambda **kwargs: fake)
    result = runner.invoke(app, ["abfp", "scan", "--target", "mqtt://127.0.0.1:1883", "--duration", "0"])
    assert result.exit_code == 0
    assert "authorized use" in result.stderr
    assert "Run only on systems you own" in result.stderr
    assert "authorized use" not in result.stdout
