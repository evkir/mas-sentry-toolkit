# SPDX-License-Identifier: AGPL-3.0-or-later
"""Payload-signature dimension."""

from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Self

from .observer import MessageEvent


@dataclass(frozen=True, slots=True)
class PayloadSignature:
    n: int
    size_mean: float
    size_stddev: float
    size_p50: int
    size_p95: int
    avg_entropy: float
    size_histogram: dict[str, int] = field(default_factory=dict)  # bucket label → count

    @classmethod
    def from_events_and_payloads(cls, events: list[MessageEvent], payloads: list[bytes]) -> Self | None:
        if not events or len(events) != len(payloads):
            return None
        sizes = [e.payload_size for e in events]
        if not sizes:
            return None
        entropies = [shannon_entropy(p) for p in payloads if p]
        avg_ent = statistics.fmean(entropies) if entropies else 0.0
        srt = sorted(sizes)
        return cls(
            n=len(events),
            size_mean=statistics.fmean(sizes),
            size_stddev=statistics.pstdev(sizes) if len(sizes) > 1 else 0.0,
            size_p50=srt[len(srt) // 2],
            size_p95=srt[int(len(srt) * 0.95)] if len(srt) >= 20 else srt[-1],
            avg_entropy=avg_ent,
            size_histogram=_bucket_sizes(sizes),
        )


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _bucket_sizes(sizes: list[int]) -> dict[str, int]:
    buckets = {"0-64": 0, "65-256": 0, "257-1024": 0, "1025-4096": 0, "4097+": 0}
    for s in sizes:
        if s <= 64:
            buckets["0-64"] += 1
        elif s <= 256:
            buckets["65-256"] += 1
        elif s <= 1024:
            buckets["257-1024"] += 1
        elif s <= 4096:
            buckets["1025-4096"] += 1
        else:
            buckets["4097+"] += 1
    return buckets
