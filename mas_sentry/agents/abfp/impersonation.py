# SPDX-License-Identifier: AGPL-3.0-or-later
"""Impersonation detector: same agent_id, materially different fingerprint.

Compares a learned baseline digest against the current run's digest for one
agent. Timing divergence (KS on inter-arrival intervals) and payload-size
divergence feed three dimensions (timing, payload, identity) that fold into
the rogue-agent score via detect_rogue's extra_dimensions hook.
"""

from __future__ import annotations

from dataclasses import dataclass

from .scoring import AnomalyScore, DimensionScore, compose
from .snapshot import AgentDigest
from .timing import TimingVector
from .timing_compare import compare_timing_series


@dataclass(frozen=True, slots=True)
class ImpersonationFinding:
    agent_id: str
    score: AnomalyScore
    timing_mismatch: bool
    payload_mismatch: bool


def _burst_dimension(baseline: AgentDigest, current: AgentDigest) -> DimensionScore:
    """Score emergence of bursty cadence or loss of periodicity vs the baseline."""
    bv = TimingVector.from_timestamps(baseline.timestamps)
    cv = TimingVector.from_timestamps(current.timestamps)
    if bv is None or cv is None:
        return DimensionScore(name="burst", raw=0.0, reason="insufficient timing samples")
    delta_burst = max(0.0, cv.burst_ratio - bv.burst_ratio)
    periodicity_loss = bv.is_periodic and not cv.is_periodic
    raw = min(1.0, delta_burst + (0.4 if periodicity_loss else 0.0))
    reason = f"burst ratio {bv.burst_ratio:.2f}->{cv.burst_ratio:.2f}"
    if periodicity_loss:
        reason += "; lost periodic cadence"
    return DimensionScore(name="burst", raw=raw, reason=reason)


def _assess(baseline: AgentDigest, current: AgentDigest) -> tuple[list[DimensionScore], bool, bool]:
    timing = compare_timing_series(baseline.timestamps, current.timestamps)
    timing_mismatch = bool(timing and not timing.similar)
    timing_raw = (1.0 - timing.p_value) if timing else 0.0

    payload_mismatch = _payload_mismatch(baseline.payload_sizes, current.payload_sizes)
    payload_raw = 0.8 if payload_mismatch else 0.0

    dims = [
        DimensionScore(name="timing", raw=timing_raw, reason="KS-test p-value below threshold"),
        DimensionScore(name="payload", raw=payload_raw, reason="Mean payload size diverged"),
        DimensionScore(
            name="identity",
            raw=0.6 if (timing_mismatch or payload_mismatch) else 0.0,
            reason="Same agent_id, divergent fingerprint",
        ),
        _burst_dimension(baseline, current),
    ]
    return dims, timing_mismatch, payload_mismatch


def impersonation_dimensions(baseline: AgentDigest, current: AgentDigest) -> list[DimensionScore]:
    """Timing/payload/identity dimensions for one agent's baseline-vs-current digests."""
    return _assess(baseline, current)[0]


def detect_impersonation(agent_id: str, baseline: AgentDigest, current: AgentDigest) -> ImpersonationFinding:
    """Wrap the impersonation dimensions into a scored finding for one agent."""
    dims, timing_mismatch, payload_mismatch = _assess(baseline, current)
    return ImpersonationFinding(
        agent_id=agent_id,
        score=compose(agent_id, dims),
        timing_mismatch=timing_mismatch,
        payload_mismatch=payload_mismatch,
    )


def _payload_mismatch(a: list[int], b: list[int]) -> bool:
    if not a or not b:
        return False
    mean_a = sum(a) / len(a)
    mean_b = sum(b) / len(b)
    if mean_a == 0:
        return mean_b > 0
    return abs(mean_b - mean_a) / mean_a > 0.5  # >50% divergence
