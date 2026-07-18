# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end: a passive scan reports unexplained temporal coupling.

Message timestamps are driven deterministically by patching the observer clock,
so the scan sees a real timing pattern rather than the microsecond-apart events
a replayed fake client would otherwise produce.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from mas_sentry.agents.abfp import observer as observer_mod
from mas_sentry.agents.abfp import runtime

SPAN = 300.0


class _FakeMsg:
    def __init__(self, topic: str, payload: bytes) -> None:
        self.topic = topic
        self.payload = payload
        self.qos = 0
        self.retain = False


def _fake_client_factory(messages: list[_FakeMsg]):
    class _FakeClient:
        def __init__(self, *_a: object, **_k: object) -> None:
            self.on_connect = None
            self.on_message = None

        def connect(self, *_a: object, **_k: object) -> None:
            if self.on_connect is not None:
                self.on_connect(self, None, None, 0)

        def subscribe(self, *_a: object, **_k: object) -> None:
            pass

        def loop_start(self) -> None:
            for m in messages:
                if self.on_message is not None:
                    self.on_message(self, None, m)

        def loop_stop(self) -> None:
            pass

        def disconnect(self) -> None:
            pass

    return _FakeClient


def _run(tmp_path: Path, stream: list[tuple[float, str]], monkeypatch) -> dict:
    """Replay (timestamp, topic) pairs in time order under a patched clock."""
    stream = sorted(stream)
    clock = iter([ts for ts, _ in stream])
    monkeypatch.setattr(observer_mod, "monotonic", lambda: next(clock))
    messages = [_FakeMsg(topic, b'{"v": 1}') for _, topic in stream]
    monkeypatch.setattr(runtime.mqtt, "Client", _fake_client_factory(messages))
    out = tmp_path / "abfp.json"
    runtime.run_abfp_scan(target="mqtt://127.0.0.1:1883", duration=0, baseline_threshold=1, out_path=out)
    return json.loads(out.read_text())


def _coupled_stream(seed: int = 4) -> list[tuple[float, str]]:
    rng = np.random.default_rng(seed)
    lead = np.sort(rng.uniform(0.0, SPAN, 120))
    follow = (lead + rng.normal(0.2, 0.05, lead.size)) % SPAN
    noise = np.sort(rng.uniform(0.0, SPAN, 120))
    return (
        [(float(t), "fleet/lead/a1/out") for t in lead]
        + [(float(t), "fleet/echo/b2/out") for t in follow]
        + [(float(t), "fleet/noise/c3/out") for t in noise]
    )


def _independent_stream(seed: int = 9) -> list[tuple[float, str]]:
    rng = np.random.default_rng(seed)
    return [(float(t), f"fleet/agent{i}/x{i}/out") for i in range(3) for t in np.sort(rng.uniform(0.0, SPAN, 120))]


def test_coupled_pair_appears_in_the_report(tmp_path: Path, monkeypatch) -> None:
    report = _run(tmp_path, _coupled_stream(), monkeypatch)

    assert "coordination" in report, "an unexplained coupled pair must be reported"
    pairs = {(c["source"], c["target"]) for c in report["coordination"]}
    assert ("fleet_lead_a1", "fleet_echo_b2") in pairs
    signal = next(c for c in report["coordination"] if c["source"] == "fleet_lead_a1")
    assert signal["z"] >= 6.0
    assert signal["observed"] > signal["null_mean"]


def test_independent_traffic_reports_no_coordination(tmp_path: Path, monkeypatch) -> None:
    report = _run(tmp_path, _independent_stream(), monkeypatch)
    assert "coordination" not in report


def test_coordination_absent_on_sparse_traffic(tmp_path: Path, monkeypatch) -> None:
    # Below the minimum event count the surrogate null is untrustworthy, so the
    # scan must stay silent rather than guess.
    stream = [(float(i) * 0.5, "fleet/lead/a1/out") for i in range(5)]
    stream += [(float(i) * 0.5 + 0.2, "fleet/echo/b2/out") for i in range(5)]
    report = _run(tmp_path, stream, monkeypatch)
    assert "coordination" not in report
