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


def compare_timings(a: list[MessageEvent], b: list[MessageEvent], alpha: float = 0.05) -> TimingSimilarity | None:
    ipis_a = _ipis(a)
    ipis_b = _ipis(b)
    if len(ipis_a) < 5 or len(ipis_b) < 5:
        return None
    stat, p = ks_2samp(ipis_a, ipis_b)
    return TimingSimilarity(ks_statistic=float(stat), p_value=float(p), similar=p > alpha)


def _ipis(events: list[MessageEvent]) -> list[float]:
    ts = sorted(e.timestamp for e in events)
    return [ts[i] - ts[i - 1] for i in range(1, len(ts))]
