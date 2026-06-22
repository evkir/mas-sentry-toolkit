# SPDX-License-Identifier: AGPL-3.0-or-later
"""compare-mode: impersonation dimensions fold into the rogue score."""

from __future__ import annotations

from mas_sentry.agents.abfp.impersonation import impersonation_dimensions
from mas_sentry.agents.abfp.rogue import detect_rogue
from mas_sentry.agents.abfp.runtime import _impersonation_dimensions
from mas_sentry.agents.abfp.snapshot import AgentDigest
from mas_sentry.agents.abfp.topic_graph import TopicGraphBuilder


def _digest(period: float = 1.0, size: int = 10, n: int = 50) -> AgentDigest:
    return AgentDigest(timestamps=[i * period for i in range(n)], payload_sizes=[size] * n)


def _graph(*pubs: tuple[str, str]):
    b = TopicGraphBuilder()
    for agent, topic in pubs:
        b.observe_publish(agent, topic)
    return b.build()


def test_dimensions_only_for_shared_agents_with_signal() -> None:
    baseline = {"agent_a": _digest(period=1.0), "ghost": _digest()}
    current = {"agent_a": _digest(period=5.0), "agent_b": _digest()}
    extra = _impersonation_dimensions(baseline, current)
    # agent_a shared + timing diverges; ghost not in current; agent_b not in baseline
    assert set(extra) == {"agent_a"}


def test_identical_digests_yield_no_dimensions() -> None:
    baseline = {"agent_a": _digest()}
    current = {"agent_a": _digest()}
    assert _impersonation_dimensions(baseline, current) == {}


def test_impersonation_only_agent_becomes_rogue_suspect() -> None:
    # Identical topology -> zero graph drift, but the timing fingerprint diverges.
    base_graph = _graph(("agent_a", "telemetry"))
    cur_graph = _graph(("agent_a", "telemetry"))
    extra = {"agent_a": impersonation_dimensions(_digest(period=1.0), _digest(period=5.0))}

    findings = detect_rogue(baseline_graph=base_graph, current_graph=cur_graph, extra_dimensions=extra)
    by_agent = {f.agent_id: f for f in findings}

    assert "agent_a" in by_agent  # surfaced despite no topology change
    dims = {d.name: d for d in by_agent["agent_a"].score.dimensions}
    assert {"timing", "identity"} <= set(dims)
    assert dims["topic"].raw == 0.0  # no spurious topology signal
    assert by_agent["agent_a"].score.total > 0
