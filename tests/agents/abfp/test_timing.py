# SPDX-License-Identifier: AGPL-3.0-or-later
from dataclasses import replace

from mas_sentry.agents.abfp import MessageEvent
from mas_sentry.agents.abfp.timing import TimingVector
from mas_sentry.agents.abfp.timing_compare import compare_timing_series, compare_timings


def _periodic(n: int = 100, period: float = 1.0, agent: str = "a") -> list[MessageEvent]:
    base = MessageEvent.now(agent, "t", b"")
    return [replace(base, timestamp=i * period) for i in range(n)]


def _bursty(n: int = 100, agent: str = "a") -> list[MessageEvent]:
    base = MessageEvent.now(agent, "t", b"")
    ts: list[float] = []
    t = 0.0
    for i in range(n):
        ts.append(t)
        t += 0.01 if i % 10 else 5.0
    return [replace(base, timestamp=x) for x in ts]


def test_timing_vector_detects_periodic():
    tv = TimingVector.from_events(_periodic())
    assert tv is not None
    assert tv.is_periodic
    assert abs(tv.ipi_mean - 1.0) < 0.01
    assert tv.cov() < 0.15


def test_timing_vector_detects_bursts():
    tv = TimingVector.from_events(_bursty())
    assert tv is not None
    assert tv.burst_ratio > 0.5
    assert not tv.is_periodic


def test_timing_vector_too_few_events():
    base = MessageEvent.now("a", "t", b"")
    assert TimingVector.from_events([base]) is None


def test_ks_compares_distributions():
    same = compare_timings(_periodic(period=1.0), _periodic(period=1.0, agent="b"))
    diff = compare_timings(_periodic(period=1.0), _periodic(period=5.0, agent="b"))
    assert same is not None and same.similar
    assert diff is not None and not diff.similar


def test_series_matches_event_path():
    a = [i * 1.0 for i in range(100)]
    b = [i * 1.0 for i in range(100)]
    c = [i * 5.0 for i in range(100)]
    same = compare_timing_series(a, b)
    diff = compare_timing_series(a, c)
    assert same is not None and same.similar
    assert diff is not None and not diff.similar


def test_series_too_few_samples_returns_none():
    assert compare_timing_series([0.0, 1.0, 2.0], [0.0, 1.0, 2.0]) is None
