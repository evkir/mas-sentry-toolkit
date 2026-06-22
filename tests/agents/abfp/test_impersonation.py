# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the impersonation detector (digest-native)."""

from __future__ import annotations

from mas_sentry.agents.abfp.impersonation import detect_impersonation, impersonation_dimensions
from mas_sentry.agents.abfp.snapshot import AgentDigest


def _digest(period: float = 1.0, size: int = 10, n: int = 50) -> AgentDigest:
    return AgentDigest(timestamps=[i * period for i in range(n)], payload_sizes=[size] * n)


def test_dimensions_named_and_zero_when_similar() -> None:
    dims = impersonation_dimensions(_digest(), _digest())
    assert [d.name for d in dims] == ["timing", "payload", "identity"]
    assert all(d.raw == 0.0 for d in dims)


def test_timing_divergence_flags_identity() -> None:
    finding = detect_impersonation("agent_a", _digest(period=1.0), _digest(period=5.0))
    assert finding.timing_mismatch
    assert not finding.payload_mismatch
    assert finding.score.total > 0
    by_name = {d.name: d for d in finding.score.dimensions}
    assert by_name["timing"].raw > 0.0
    assert by_name["identity"].raw > 0.0


def test_payload_divergence_flags_identity() -> None:
    finding = detect_impersonation("agent_a", _digest(size=10), _digest(size=100))
    assert finding.payload_mismatch
    assert not finding.timing_mismatch
    by_name = {d.name: d for d in finding.score.dimensions}
    assert by_name["payload"].raw == 0.8
    assert by_name["identity"].raw > 0.0


def test_similar_digests_no_impersonation() -> None:
    finding = detect_impersonation("agent_a", _digest(), _digest())
    assert not finding.timing_mismatch
    assert not finding.payload_mismatch
    assert finding.score.total == 0


def test_empty_digests_are_safe() -> None:
    dims = impersonation_dimensions(AgentDigest(), AgentDigest())
    assert all(d.raw == 0.0 for d in dims)


def test_zero_mean_baseline_payload_flags_divergence() -> None:
    finding = detect_impersonation("agent_a", _digest(size=0), _digest(size=10))
    assert finding.payload_mismatch
