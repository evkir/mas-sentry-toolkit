# SPDX-License-Identifier: AGPL-3.0-or-later
"""Impersonation detector: same agent_id, materially different fingerprint."""

from __future__ import annotations

from dataclasses import dataclass

from .observer import MessageEvent
from .scoring import AnomalyScore, DimensionScore, compose
from .timing_compare import compare_timings


@dataclass(frozen=True, slots=True)
class ImpersonationFinding:
    agent_id: str
    score: AnomalyScore
    timing_mismatch: bool
    payload_mismatch: bool


def detect_impersonation(
    agent_id: str,
    baseline_events: list[MessageEvent],
    current_events: list[MessageEvent],
    baseline_payload_sizes: list[int] | None = None,
    current_payload_sizes: list[int] | None = None,
) -> ImpersonationFinding:
    timing = compare_timings(baseline_events, current_events)
    timing_mismatch = bool(timing and not timing.similar)
    timing_raw = (1.0 - timing.p_value) if timing else 0.0

    payload_mismatch = _payload_mismatch(baseline_payload_sizes, current_payload_sizes)
    payload_raw = 0.8 if payload_mismatch else 0.0

    dims = [
        DimensionScore(name="timing", raw=timing_raw, reason="KS-test p-value below threshold"),
        DimensionScore(name="payload", raw=payload_raw, reason="Mean payload size diverged"),
        DimensionScore(
            name="identity",
            raw=0.6 if (timing_mismatch or payload_mismatch) else 0.0,
            reason="Same agent_id, divergent fingerprint",
        ),
    ]
    return ImpersonationFinding(
        agent_id=agent_id,
        score=compose(agent_id, dims),
        timing_mismatch=timing_mismatch,
        payload_mismatch=payload_mismatch,
    )


def _payload_mismatch(a: list[int] | None, b: list[int] | None) -> bool:
    if not a or not b:
        return False
    mean_a = sum(a) / len(a)
    mean_b = sum(b) / len(b)
    if mean_a == 0:
        return mean_b > 0
    return abs(mean_b - mean_a) / mean_a > 0.5  # >50% divergence
