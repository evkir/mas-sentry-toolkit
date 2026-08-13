# SPDX-License-Identifier: AGPL-3.0-or-later
"""Side-channel detection of unexplained coordination between agents.

This is NOT a collusion detector, and the distinction matters. State-of-the-art
collusion detection (NARCBench, 2026) reads model activations, which a network
scanner does not have; and against steganographic collusion, plain-text
monitoring is theoretically defeated - schemes exist that are computationally
indistinguishable from good-faith traffic. Claiming to detect collusion here
would be selling something this tool cannot do.

What a passive observer *can* do is measure the consequences of coordination as
a side channel: if agent B systematically publishes shortly after agent A, the
two are coupled, whatever the content says. That coupling is only interesting
when the topic graph does not already explain it - a pipeline agent answering
its upstream is normal engineering. A pair that is temporally locked with no
observed publish/subscribe path between them is coordinating through a channel
this scan cannot see, which is a lead worth investigating, not a verdict.

Method: for an ordered pair (A, B), the statistic is the fraction of A events
followed by a B event inside a response window. That number alone is
meaningless - two agents on the same timer score high without coordinating - so
it is standardised against a circular-shift surrogate null. Shifting B in time
preserves its own cadence and burstiness exactly, and destroys only the phase
relationship with A. The reported z is how many surrogate standard deviations
the real coupling exceeds that null.

Known limits, by construction:
- If both agents are strictly periodic, a shift cannot break the alignment, so
  genuine coupling is indistinguishable from a shared timer and is NOT reported.
  The test fails toward silence rather than toward a false accusation.
- A response lag longer than the target typical inter-publish interval is not
  seen, because the statistic looks at the next event, not a distant one.
- A response window wider than the target cadence self-cancels: the null rises
  with the observation, the variance collapses, and z is reported as zero.

Taxonomy: CWE-514 (covert channel) / STRIDE Information Disclosure / ASI07.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx
import numpy as np

# A response is only credited if it lands within this many seconds of the
# triggering event. Wider than a real answer delay only adds noise.
DEFAULT_WINDOW_S = 0.5
# Surrogate shifts per pair. 200 puts the null mean/sd well within tolerance at
# roughly 6 ms per pair; the z resolution does not depend on this count, unlike
# a rank-based p-value whose floor is 1/(K+1).
DEFAULT_SURROGATES = 200
# Six sigma against a null measured as N(0,1): on a clean 380-pair mesh the
# largest observed z was 2.94, so this leaves a wide margin over noise.
DEFAULT_Z_THRESHOLD = 6.0
# Below this many events the surrogate null is too coarse to trust.
MIN_EVENTS = 20
# Pair count grows quadratically; refuse to stall the scan on a large mesh.
MAX_AGENTS = 40


@dataclass(frozen=True, slots=True)
class CoordinationSignal:
    """One ordered pair whose timing coupling the topic graph does not explain."""

    source: str
    target: str
    z: float
    observed: float
    null_mean: float
    events: int


def _followed_fraction(src: np.ndarray, dst: np.ndarray, window: float) -> float:
    """Fraction of src events followed by a dst event within the window."""
    if src.size == 0 or dst.size == 0:
        return 0.0
    idx = np.searchsorted(dst, src, side="left")
    inside = idx < dst.size
    if not inside.any():
        return 0.0
    lags = dst[idx[inside]] - src[inside]
    return float(np.count_nonzero(lags <= window) / src.size)


def coupling_z(
    src: np.ndarray,
    dst: np.ndarray,
    span: float,
    window: float = DEFAULT_WINDOW_S,
    surrogates: int = DEFAULT_SURROGATES,
    seed: int = 0,
) -> tuple[float, float, float]:
    """Standardised response coupling of dst on src: (z, observed, null mean).

    The null is built by circularly shifting dst within the observation span,
    which keeps its cadence intact and removes only its phase relative to src.
    A degenerate null (zero variance) yields z = 0 rather than a division blow-up,
    which is what silently happens when the window exceeds the dst cadence.
    """
    observed = _followed_fraction(src, dst, window)
    rng = np.random.default_rng(seed)
    null = np.empty(surrogates)
    for i in range(surrogates):
        shifted = np.sort((dst + rng.uniform(0.0, span)) % span)
        null[i] = _followed_fraction(src, shifted, window)
    sd = float(null.std())
    mean = float(null.mean())
    if sd < 1e-9:
        return 0.0, observed, mean
    return (observed - mean) / sd, observed, mean


def _explained_by_graph(graph: nx.DiGraph, a: str, b: str) -> bool:
    """True when the observed topic graph already accounts for a -> b."""
    if a not in graph or b not in graph:
        return False
    return nx.has_path(graph, a, b)


def detect_coordination(
    series: dict[str, list[float]],
    graph: nx.DiGraph,
    window: float = DEFAULT_WINDOW_S,
    z_threshold: float = DEFAULT_Z_THRESHOLD,
    surrogates: int = DEFAULT_SURROGATES,
    seed: int = 0,
) -> list[CoordinationSignal]:
    """Report ordered pairs coupled in time with no path in the topic graph.

    Pairs already connected through a published/consumed topic are skipped: a
    downstream agent answering its upstream is the system working. Agents with
    too few events are skipped because the surrogate null would be unreliable,
    and an oversized mesh is refused outright rather than stalling the scan.
    """
    usable = {aid: sorted(ts) for aid, ts in series.items() if len(ts) >= MIN_EVENTS}
    if len(usable) < 2 or len(usable) > MAX_AGENTS:
        return []
    flat = [t for ts in usable.values() for t in ts]
    span = max(flat) - min(flat)
    if span <= 0:
        return []
    arrays = {aid: np.asarray(ts, dtype=float) for aid, ts in usable.items()}

    signals: list[CoordinationSignal] = []
    for src_id, src in arrays.items():
        for dst_id, dst in arrays.items():
            if src_id == dst_id or _explained_by_graph(graph, src_id, dst_id):
                continue
            z, observed, null_mean = coupling_z(src, dst, span, window, surrogates, seed)
            if z >= z_threshold:
                signals.append(
                    CoordinationSignal(
                        source=src_id,
                        target=dst_id,
                        z=round(z, 2),
                        observed=round(observed, 3),
                        null_mean=round(null_mean, 3),
                        events=int(src.size),
                    )
                )
    signals.sort(key=lambda s: s.z, reverse=True)
    return signals
