# SPDX-License-Identifier: AGPL-3.0-or-later
"""Timing-cadence dimension of the ABFP fingerprint."""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Self

from .observer import MessageEvent


@dataclass(frozen=True, slots=True)
class TimingVector:
    """Statistical fingerprint of inter-publish intervals (IPI)."""

    n: int
    ipi_mean: float
    ipi_stddev: float
    ipi_p50: float
    ipi_p95: float
    burst_ratio: float  # fraction of IPIs below mean/4 (bursts)
    is_periodic: bool

    @classmethod
    def from_events(cls, events: list[MessageEvent]) -> Self | None:
        return cls.from_timestamps([e.timestamp for e in events])

    @classmethod
    def from_timestamps(cls, timestamps: list[float]) -> Self | None:
        """Build a timing fingerprint from raw message timestamps (digest-native entry)."""
        if len(timestamps) < 3:
            return None
        ts = sorted(timestamps)
        ipis = [ts[i] - ts[i - 1] for i in range(1, len(ts))]
        if not ipis:
            return None
        mean = statistics.fmean(ipis)
        sd = statistics.pstdev(ipis) if len(ipis) > 1 else 0.0
        srt = sorted(ipis)
        p50 = srt[len(srt) // 2]
        p95 = srt[int(len(srt) * 0.95)] if len(srt) >= 20 else srt[-1]
        burst = sum(1 for x in ipis if x < mean / 4) / len(ipis) if mean > 0 else 0.0
        # heuristic: periodic if stddev / mean < 0.15 (CoV)
        periodic = mean > 0 and (sd / mean) < 0.15
        return cls(
            n=len(ts),
            ipi_mean=mean,
            ipi_stddev=sd,
            ipi_p50=p50,
            ipi_p95=p95,
            burst_ratio=burst,
            is_periodic=periodic,
        )

    def cov(self) -> float:
        """Coefficient of variation (stddev / mean)."""
        return self.ipi_stddev / self.ipi_mean if self.ipi_mean > 0 else 0.0
