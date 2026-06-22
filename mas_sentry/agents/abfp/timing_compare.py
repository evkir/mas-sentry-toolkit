# SPDX-License-Identifier: AGPL-3.0-or-later
"""Compare TimingVectors via Kolmogorov-Smirnov on IPI distributions."""

from __future__ import annotations

from dataclasses import dataclass

from scipy.stats import ks_2samp

from .observer import MessageEvent


@dataclass(frozen=True, slots=True)
class TimingSimilarity:
    ks_statistic: float
    p_value: float
    similar: bool  # p > 0.05 → cannot reject same-distribution null


def compare_timing_series(ts_a: list[float], ts_b: list[float], alpha: float = 0.05) -> TimingSimilarity | None:
    """Kolmogorov-Smirnov over inter-arrival intervals of two timestamp series."""
    ipis_a = _ipis(ts_a)
    ipis_b = _ipis(ts_b)
    if len(ipis_a) < 5 or len(ipis_b) < 5:
        return None
    stat, p = ks_2samp(ipis_a, ipis_b)
    return TimingSimilarity(ks_statistic=float(stat), p_value=float(p), similar=p > alpha)


def compare_timings(a: list[MessageEvent], b: list[MessageEvent], alpha: float = 0.05) -> TimingSimilarity | None:
    """Backward-compatible wrapper: compare two MessageEvent streams by their timestamps."""
    return compare_timing_series([e.timestamp for e in a], [e.timestamp for e in b], alpha)


def _ipis(timestamps: list[float]) -> list[float]:
    ts = sorted(timestamps)
    return [ts[i] - ts[i - 1] for i in range(1, len(ts))]
