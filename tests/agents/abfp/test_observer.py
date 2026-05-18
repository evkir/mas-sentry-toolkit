# SPDX-License-Identifier: AGPL-3.0-or-later
from mas_sentry.agents.abfp import MessageEvent, MessageObserver
from mas_sentry.agents.abfp.baseline import BaselineCollector
from mas_sentry.agents.abfp.identity import infer_agent_id


def _ev(aid: str, topic: str = "x/y/1", size: int = 32) -> MessageEvent:
    return MessageEvent.now(aid, topic, b"\x00" * size)


def test_observer_records_and_indexes_by_agent():
    obs = MessageObserver(max_per_agent=10)
    obs.record(_ev("a"))
    obs.record(_ev("a"))
    obs.record(_ev("b"))
    assert set(obs.agent_ids()) == {"a", "b"}
    assert obs.count_for("a") == 2
    assert obs.count_for("b") == 1
    assert obs.total_observed == 3


def test_observer_ring_buffer_bounded():
    obs = MessageObserver(max_per_agent=5)
    for _ in range(20):
        obs.record(_ev("a"))
    assert obs.count_for("a") == 5
    assert obs.total_observed == 20


def test_baseline_threshold_gates_readiness():
    obs = MessageObserver(max_per_agent=2000)
    col = BaselineCollector(obs, threshold=500)
    for _ in range(499):
        obs.record(_ev("a"))
    assert not col.status("a").ready
    obs.record(_ev("a"))
    assert col.status("a").ready
    assert col.ready_agents() == ["a"]


def test_identity_uses_client_id_when_meaningful():
    assert infer_agent_id("sensor-kitchen-01", "home/temp") == "sensor-kitchen-01"


def test_identity_falls_back_for_random_client_id():
    aid = infer_agent_id("mqttjs_abc123", "factory/robot/r17/state")
    assert aid == "factory_robot_r17"


def test_identity_pure_fallback():
    assert infer_agent_id(None, "sys/heartbeat") == "inferred_sys"
    assert infer_agent_id("", "") == "inferred_unknown"
