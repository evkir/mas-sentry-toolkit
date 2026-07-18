# SPDX-License-Identifier: AGPL-3.0-or-later
"""Passive exfiltration-channel detection over live agent traffic.

Sibling to payload_injection: that module flags injection directives arriving
in an agent published payload (the cause); this flags auto-fetch exfiltration
channels an agent emits (the effect). When a compromised agent publishes a
Markdown image, reference-style link, or HTML img pointing at an external URL,
any consumer that renders the message - a dashboard, an operator console, a
downstream LLM - fetches it, carrying whatever data was folded into the URL out
of the mesh (the EchoLeak / ForcedLeak class, seen here on the message bus).

Why the bus and not only the final answer: the 2026 AgentLeak evaluation found
inter-agent coordination channels to be the highest-yield exfiltration vector
precisely because they stay invisible to output-level defenses. A scanner that
only inspects an agent final response never sees this.

Payloads are scanned in-flight and NOT retained (only channel kind, host and a
sample URL are kept), so this adds no message-buffer memory pressure. External
http(s) targets are what the shared primitive reports; relative paths and data
URIs are already excluded there because they trigger no external fetch.

Taxonomy: CWE-201 / STRIDE Information Disclosure / ASI02 / OWASP LLM05.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from mas_sentry.core.output_exfil import scan_exfiltration_channels

from .scoring import DimensionScore

# Mirror the injection scanner cap: beacons sit inline in the rendered body,
# and an unbounded scan over multi-megabyte payloads would stall the MQTT loop.
_MAX_SCAN_BYTES = 4096


def scan_payload_exfil(payload: bytes) -> list[tuple[str, str]]:
    """Return distinct (channel kind, url) pairs found in a raw payload."""
    text = payload[:_MAX_SCAN_BYTES].decode("utf-8", errors="ignore")
    return [(c.kind, c.url) for c in scan_exfiltration_channels(text)]


def _host(url: str) -> str:
    return urlsplit(url).netloc or url


@dataclass
class _AgentChannels:
    channels: set[tuple[str, str]] = field(default_factory=set)  # (kind, host)
    hit_count: int = 0
    sample_topic: str = ""
    sample_url: str = ""


@dataclass
class PayloadExfilTracker:
    """Accumulates per-agent exfiltration-channel hits across the scan window."""

    _by_agent: dict[str, _AgentChannels] = field(default_factory=dict)

    def observe(self, agent_id: str, topic: str, payload: bytes) -> None:
        found = scan_payload_exfil(payload)
        if not found:
            return
        seen = self._by_agent.get(agent_id)
        if seen is None:
            seen = _AgentChannels(sample_topic=topic, sample_url=found[0][1])
            self._by_agent[agent_id] = seen
        seen.channels.update((kind, _host(url)) for kind, url in found)
        seen.hit_count += 1

    def dimensions(self) -> dict[str, list[DimensionScore]]:
        """Build the per-agent ``exfil`` DimensionScore for detect_rogue."""
        return {
            agent_id: [
                DimensionScore(
                    name="exfil",
                    raw=_exfil_raw(seen.channels),
                    reason=_exfil_reason(seen),
                )
            ]
            for agent_id, seen in self._by_agent.items()
        }


def _exfil_raw(channels: set[tuple[str, str]]) -> float:
    """Scale 0..1 by how many distinct (kind, host) channels an agent emits.

    Called only for agents that already have at least one channel recorded.
    One external auto-fetch channel is already the signal; each additional
    distinct kind or destination host compounds it. Deliberately below the
    injection ceiling: an agent legitimately publishing an external image is
    plausible, so the finding informs the operator rather than convicting on
    its own - the destination is always named in the reason.
    """
    return min(1.0, 0.55 + 0.1 * (len(channels) - 1))


def _exfil_reason(seen: _AgentChannels) -> str:
    listed = ", ".join(f"{kind} -> {host}" for kind, host in sorted(seen.channels))
    return (
        f"Auto-fetch exfiltration channel(s) in published payload(s): {listed} "
        f"({seen.hit_count} message(s), e.g. topic '{seen.sample_topic}', url {seen.sample_url})"
    )
