# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the management API hands over has to arrive as Findings, not as a table."""

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.core.finding import Severity
from mas_sentry.protocols import amqp_runtime as rt

runner = CliRunner()


class _Analyzer:
    reachable: ClassVar[bool] = True
    guest: ClassVar[bool] = True
    bindings: ClassVar[list[dict[str, Any]]] = []

    def __init__(self, host: str, **kw: Any) -> None:
        self.host = host

    def connect(self) -> bool:
        return _Analyzer.reachable

    def check_default_credentials(self) -> bool:
        return _Analyzer.guest

    def enumerate_exchanges(self) -> list[dict[str, Any]]:
        return [{"name": ""}, {"name": "agent.events"}]

    def enumerate_queues(self) -> list[dict[str, Any]]:
        return [{"name": "agent-cmd", "messages": 12, "consumers": 0}, {"name": "idle", "consumers": 3}]

    def enumerate_connections(self) -> list[dict[str, Any]]:
        return []

    def enumerate_bindings(self) -> list[dict[str, Any]]:
        return list(_Analyzer.bindings)


@pytest.fixture(autouse=True)
def _stub(monkeypatch: pytest.MonkeyPatch) -> None:
    _Analyzer.reachable = True
    _Analyzer.guest = True
    _Analyzer.bindings = []
    monkeypatch.setattr(rt, "AMQPAnalyzer", _Analyzer)


def test_the_default_account_is_critical(tmp_path: Path) -> None:
    findings = rt.run_amqp_scan("127.0.0.1", out=tmp_path / "a.json")
    creds = [f for f in findings if "guest" in f.title]
    assert creds[0].severity is Severity.CRITICAL
    assert "CWE-1392" in creds[0].tags


def test_a_refused_guest_is_not_reported_as_absent(tmp_path: Path) -> None:
    """RabbitMQ refuses guest off loopback by default, so a refusal proves nothing about the account."""
    _Analyzer.guest = False
    findings = rt.run_amqp_scan("127.0.0.1", out=tmp_path / "a.json")
    creds = [f for f in findings if "guest" in f.title]
    assert creds[0].severity is Severity.INFO
    assert "not proof" in creds[0].detail


def test_an_unreachable_api_is_a_gap_not_a_pass(tmp_path: Path) -> None:
    _Analyzer.reachable = False
    findings = rt.run_amqp_scan("127.0.0.1", out=tmp_path / "a.json")
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "enumeration_gap" in findings[0].tags
    assert "not a clean result" in findings[0].detail


def test_a_trace_binding_is_reported_as_a_copy_of_the_traffic(tmp_path: Path) -> None:
    _Analyzer.bindings = [
        {"source": "", "destination": "agent-cmd"},
        {"source": "amq.rabbitmq.trace", "destination": "tap", "routing_key": "#"},
    ]
    findings = rt.run_amqp_scan("127.0.0.1", out=tmp_path / "a.json")
    traced = [f for f in findings if "tracing" in f.title]
    assert traced[0].severity is Severity.HIGH
    assert traced[0].evidence["sinks"] == ["tap"]


def test_ordinary_bindings_do_not_fire_the_trace_check(tmp_path: Path) -> None:
    """The check must be silent on a broker that simply has bindings, which is all of them."""
    _Analyzer.bindings = [{"source": "amq.topic", "destination": "agent-cmd"}]
    findings = rt.run_amqp_scan("127.0.0.1", out=tmp_path / "a.json")
    assert [f for f in findings if "tracing" in f.title] == []


def test_the_inventory_notes_a_backlog_with_no_consumer(tmp_path: Path) -> None:
    findings = rt.run_amqp_scan("127.0.0.1", out=tmp_path / "a.json")
    inventory = next(f for f in findings if "Topology readable" in f.title)
    assert inventory.evidence["queues_with_backlog_and_no_consumer"] == ["agent-cmd"]
    assert inventory.severity is Severity.INFO


def test_findings_reach_the_report_file(tmp_path: Path) -> None:
    out = tmp_path / "amqp.json"
    rt.run_amqp_scan("127.0.0.1", out=out)
    payload = json.loads(out.read_text())
    assert payload["summary"]["total"] >= 2
    assert all(f["module"] == "amqp.management" for f in payload["findings"])


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("rabbit.test", ("rabbit.test", 15672)),
        ("rabbit.test:8080", ("rabbit.test", 8080)),
        ("amqp://rabbit.test:15672/", ("rabbit.test", 15672)),
        ("http://127.0.0.1:15672", ("127.0.0.1", 15672)),
        ("[::1]:15672", ("::1", 15672)),
    ],
)
def test_target_parsing(target: str, expected: tuple[str, int]) -> None:
    assert rt.parse_target(target) == expected


@pytest.mark.parametrize("bad", ["", "host:0", "host:notaport", "[::1"])
def test_bad_targets_are_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        rt.parse_target(bad)


def test_the_cli_reaches_the_scan(tmp_path: Path) -> None:
    """The module was importable and correct for months; nothing called it."""
    out = tmp_path / "cli.json"
    result = runner.invoke(app, ["amqp", "scan", "--target", "127.0.0.1", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_a_non_lab_target_needs_scope_confirmation(tmp_path: Path) -> None:
    result = runner.invoke(app, ["amqp", "scan", "--target", "rabbit.example.com", "--out", str(tmp_path / "x.json")])
    assert result.exit_code != 0
