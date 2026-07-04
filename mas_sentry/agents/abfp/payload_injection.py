# SPDX-License-Identifier: AGPL-3.0-or-later
"""Passive indirect-prompt-injection detection over live agent traffic.

The MQTT loop hands every observed payload here. When an agent publishes
injection directives into the topic graph - because it was poisoned upstream
or is malicious - the consuming agents downstream inherit the contaminated
content. We surface the emitting agent as an ABFP scoring dimension
(name="injection"); the existing cascade.blast_radius then quantifies the
downstream reach over the same topic graph.

Payloads are scanned in-flight and NOT retained (the observer keeps only
size + hash), so this adds no message-buffer memory pressure.

Taxonomy: CWE-1427 / STRIDE Tampering / ASI01 Goal Hijack / AML.T0051.
"""

from __future__ import annotations

import hashlib
import time
from collections import deque
from dataclasses import dataclass, field

from mas_sentry.core.injection_scan import STRONG_PATTERNS, scan_string

from .injection_propagation import InjectionEvent
from .scoring import DimensionScore

# Cap scanned bytes per payload: injection directives are front-loaded, and an
# unbounded scan over multi-megabyte payloads would stall the MQTT loop.
_MAX_SCAN_BYTES = 4096
# Bounded ring of injection events feeding the propagation graph. Only hits
# are recorded (patterns + hash, never the payload), so memory stays capped
# regardless of traffic volume.
_MAX_EVENTS = 4096


def scan_payload(payload: bytes) -> list[str]:
    """Return the distinct injection-pattern names found in a raw payload."""
    text = payload[:_MAX_SCAN_BYTES].decode("utf-8", errors="ignore")
    return [m.pattern for m in scan_string(text)]


@dataclass
class _AgentHits:
    patterns: set[str] = field(default_factory=set)
    hit_count: int = 0
    sample_topic: str = ""


@dataclass
class PayloadInjectionTracker:
    """Accumulates per-agent injection-pattern hits across the scan window."""

    _by_agent: dict[str, _AgentHits] = field(default_factory=dict)
    _events: deque[InjectionEvent] = field(default_factory=lambda: deque(maxlen=_MAX_EVENTS))

    def observe(self, agent_id: str, topic: str, payload: bytes) -> None:
        patterns = scan_payload(payload)
        if not patterns:
            return
        hits = self._by_agent.get(agent_id)
        if hits is None:
            hits = _AgentHits(sample_topic=topic)
            self._by_agent[agent_id] = hits
        hits.patterns.update(patterns)
        hits.hit_count += 1
        self._events.append(
            InjectionEvent(
                agent_id=agent_id,
                topic=topic,
                timestamp=time.monotonic(),
                patterns=frozenset(patterns),
                payload_hash=hashlib.sha1(payload, usedforsecurity=False).hexdigest()[:16],
            )
        )

    def events(self) -> list[InjectionEvent]:
        """Injection events in observation order, for the propagation graph."""
        return list(self._events)

    def dimensions(self) -> dict[str, list[DimensionScore]]:
        """Build the per-agent ``injection`` DimensionScore for detect_rogue."""
        out: dict[str, list[DimensionScore]] = {}
        for agent_id, hits in self._by_agent.items():
            out[agent_id] = [
                DimensionScore(
                    name="injection",
                    raw=_injection_raw(hits.patterns),
                    reason=_injection_reason(hits),
                )
            ]
        return out


def _injection_raw(patterns: set[str]) -> float:
    """Scale 0..1 by pattern strength, not raw count.

    A single strong directive (obfuscation / ignore-previous / tool-call
    hijack) already warrants escalation; ambient matches (new-task /
    system-role) start lower. Each additional distinct pattern adds signal.
    """
    if not patterns:
        return 0.0
    base = 0.8 if patterns & STRONG_PATTERNS else 0.5
    extra = 0.1 * (len(patterns) - 1)
    return min(1.0, base + extra)


def _injection_reason(hits: _AgentHits) -> str:
    pats = ", ".join(sorted(hits.patterns))
    return (
        f"Injection directive(s) in published payload(s): {pats} "
        f"({hits.hit_count} message(s), e.g. topic '{hits.sample_topic}')"
    )
