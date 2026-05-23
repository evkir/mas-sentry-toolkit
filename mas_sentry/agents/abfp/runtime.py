# SPDX-License-Identifier: AGPL-3.0-or-later
"""Glue: MQTT live-collection -> fingerprint -> score -> report."""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlparse

import paho.mqtt.client as mqtt  # type: ignore[import-not-found]
from rich.console import Console

from .baseline import BaselineCollector
from .identity import infer_agent_id
from .observer import MessageEvent, MessageObserver
from .rogue import RogueFinding, detect_rogue
from .topic_graph import TopicGraphBuilder

console = Console()


def run_abfp_scan(
    target: str,
    duration: int,
    baseline_threshold: int,
    out_path: Path,
) -> list[RogueFinding]:
    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 1883

    observer = MessageObserver()
    graph_builder = TopicGraphBuilder()

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)  # type: ignore[attr-defined]

    def on_connect(c, _u, _f, _rc, _props=None):
        c.subscribe("#", qos=0)
        c.subscribe("$SYS/#", qos=0)
        console.print(f"[green][abfp] connected to {host}:{port}[/green]")

    def on_message(_c, _u, msg):
        agent_id = infer_agent_id(getattr(msg, "client_id", None), msg.topic)
        ev = MessageEvent.now(agent_id, msg.topic, msg.payload, msg.qos, bool(msg.retain))
        observer.record(ev)
        graph_builder.observe_publish(agent_id, msg.topic)

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, port, keepalive=30)
    client.loop_start()
    time.sleep(duration)
    client.loop_stop()
    client.disconnect()

    bc = BaselineCollector(observer, threshold=baseline_threshold)
    current_graph = graph_builder.build()
    # First-run: baseline == current. Drift detection requires a prior run.
    findings = detect_rogue(baseline_graph=current_graph, current_graph=current_graph)
    _write_report(out_path, findings, baseline_status=bc.all_statuses(), target=target)
    return findings


def _write_report(out_path: Path, findings: list[RogueFinding], baseline_status, target: str) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "target": target,
        "baseline": [s.__dict__ for s in baseline_status],
        "findings": [
            {
                "agent_id": f.agent_id,
                "total": f.score.total,
                "severity": f.score.severity.value,
                "diff": f.diff_summary,
            }
            for f in findings
        ],
    }
    out_path.write_text(json.dumps(payload, indent=2, default=str))
