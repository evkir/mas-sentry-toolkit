# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for side-channel coordination detection.

Series are synthetic timestamp streams. The confounder cases matter as much as
the positive ones: a shared timer must stay silent, or the check is unusable.
"""

from __future__ import annotations

import networkx as nx
import numpy as np
import pytest

from mas_sentry.agents.abfp.coordination import (
    CoordinationSignal,
    coupling_z,
    detect_coordination,
)

SPAN = 300.0


def _rng(seed: int = 5) -> np.random.Generator:
    return np.random.default_rng(seed)


def _poisson(rate: float, rng: np.random.Generator) -> np.ndarray:
    return np.sort(rng.uniform(0.0, SPAN, rng.poisson(rate * SPAN)))


def _periodic(period: float, phase: float) -> np.ndarray:
    return np.sort((np.arange(0.0, SPAN, period) + phase) % SPAN)


def _answers(src: np.ndarray, rng: np.random.Generator, lag: float = 0.2) -> np.ndarray:
    return np.sort((src + rng.normal(lag, 0.05, src.size)) % SPAN)


# --- the statistic itself ---


def test_coupled_pair_scores_far_above_null() -> None:
    rng = _rng()
    src = _poisson(0.5, rng)
    z, observed, null_mean = coupling_z(src, _answers(src, rng), SPAN)
    assert z > 10.0
    assert observed > 0.9
    assert null_mean < 0.4


def test_independent_pair_is_near_zero() -> None:
    rng = _rng()
    z, _, _ = coupling_z(_poisson(0.5, rng), _poisson(0.5, rng), SPAN)
    assert abs(z) < 6.0


def test_shared_timer_is_not_flagged() -> None:
    # The confounder: identical periods, unrelated phases, zero coordination.
    # A circular shift preserves the cadence, so the null matches the observation.
    z, _, _ = coupling_z(_periodic(2.0, 0.0), _periodic(2.0, 0.35), SPAN)
    assert z < 6.0


def test_partial_coupling_still_detected() -> None:
    rng = _rng()
    src = _poisson(0.5, rng)
    mask = rng.random(src.size) < 0.4
    replies = np.sort(np.concatenate([_answers(src[mask], rng), _poisson(0.3, rng)]))
    z, _, _ = coupling_z(src, replies, SPAN)
    assert z > 6.0


def test_oversized_window_cannot_manufacture_a_signal() -> None:
    # A window far wider than the target cadence scores ~1.0 on the real data,
    # but every surrogate scores ~1.0 too, so the pair stays well below threshold.
    rng = _rng()
    src = _poisson(0.5, rng)
    z, observed, null_mean = coupling_z(src, _poisson(5.0, rng), SPAN, window=60.0)
    assert observed > 0.99
    assert null_mean > 0.99
    assert z < 6.0


def test_fully_saturated_null_yields_exactly_zero() -> None:
    # Dense regular target: every shift lands a hit for every source event, so
    # the null variance is exactly zero and the statistic must not divide by it.
    src = _poisson(0.5, _rng())
    dst = np.arange(0.0, SPAN, 0.1)
    z, observed, _ = coupling_z(src, dst, SPAN, window=0.5)
    assert observed == 1.0
    assert z == 0.0


def test_source_entirely_after_target_scores_zero() -> None:
    # No source event has any following target event at all.
    dst = np.linspace(0.0, 10.0, 30)
    src = np.linspace(200.0, 250.0, 30)
    z, observed, _ = coupling_z(src, dst, SPAN)
    assert observed == 0.0
    # Below its own surrogate null, so the z is negative - never a report.
    assert z <= 0.0


def test_empty_series_scores_zero() -> None:
    z, observed, _ = coupling_z(np.array([]), np.array([1.0, 2.0]), SPAN)
    assert observed == 0.0
    assert z == 0.0


def test_result_is_deterministic_for_a_seed() -> None:
    rng = _rng()
    src = _poisson(0.5, rng)
    dst = _answers(src, rng)
    assert coupling_z(src, dst, SPAN, seed=1) == coupling_z(src, dst, SPAN, seed=1)


# --- pair sweep ---


def _series(rng: np.random.Generator) -> dict[str, list[float]]:
    src = _poisson(0.5, rng)
    return {
        "planner": list(src),
        "worker": list(_answers(src, rng)),
        "logger": list(_poisson(0.5, rng)),
    }


def test_unexplained_pair_is_reported() -> None:
    signals = detect_coordination(_series(_rng()), nx.DiGraph())
    assert [(s.source, s.target) for s in signals] == [("planner", "worker")]
    assert signals[0].z > 10.0
    assert signals[0].events >= 20


def test_pair_explained_by_topic_path_is_skipped() -> None:
    # planner publishes a topic that worker consumes: answering upstream is normal.
    graph = nx.DiGraph()
    graph.add_edge("planner", "tasks/out")
    graph.add_edge("tasks/out", "worker")
    assert detect_coordination(_series(_rng()), graph) == []


def test_partial_graph_still_reports_the_unexplained_direction() -> None:
    # Only worker -> planner is wired; the coupled planner -> worker stays unexplained.
    graph = nx.DiGraph()
    graph.add_edge("worker", "results/out")
    graph.add_edge("results/out", "logger")
    signals = detect_coordination(_series(_rng()), graph)
    assert ("planner", "worker") in [(s.source, s.target) for s in signals]


def test_sparse_agents_are_skipped() -> None:
    rng = _rng()
    src = _poisson(0.5, rng)
    series = {"planner": list(src), "chatty": list(_answers(src, rng))[:5]}
    assert detect_coordination(series, nx.DiGraph()) == []


def test_single_agent_yields_nothing() -> None:
    assert detect_coordination({"solo": list(_poisson(0.5, _rng()))}, nx.DiGraph()) == []


def test_oversized_mesh_is_refused() -> None:
    rng = _rng()
    series = {f"a{i}": list(_poisson(0.5, rng)) for i in range(41)}
    assert detect_coordination(series, nx.DiGraph()) == []


def test_zero_span_yields_nothing() -> None:
    series = {"a": [1.0] * 25, "b": [1.0] * 25}
    assert detect_coordination(series, nx.DiGraph()) == []


def test_signals_sorted_by_strength() -> None:
    rng = _rng()
    src = _poisson(0.5, rng)
    strong = _answers(src, rng)
    mask = rng.random(src.size) < 0.4
    weak = np.sort(np.concatenate([_answers(src[mask], rng), _poisson(0.3, rng)]))
    signals = detect_coordination({"src": list(src), "strong": list(strong), "weak": list(weak)}, nx.DiGraph())
    zs = [s.z for s in signals]
    assert zs == sorted(zs, reverse=True)


@pytest.mark.parametrize("threshold", [6.0, 12.0])
def test_threshold_gates_reporting(threshold: float) -> None:
    signals = detect_coordination(_series(_rng()), nx.DiGraph(), z_threshold=threshold)
    assert all(s.z >= threshold for s in signals)


def test_signal_is_frozen() -> None:
    sig = CoordinationSignal("a", "b", 9.0, 0.9, 0.2, 30)
    with pytest.raises(AttributeError):
        sig.z = 1.0  # type: ignore[misc]
