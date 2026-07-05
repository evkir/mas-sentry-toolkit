# SPDX-License-Identifier: AGPL-3.0-or-later
"""Glue: MQTT live-collection -> fingerprint -> score -> report."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import paho.mqtt.client as mqtt
from rich.console import Console

from .baseline import BaselineCollector
from .cascade import BlastRadius, blast_radius
from .graph_metrics import AgentGraphMetrics, all_metrics, graph_summary
from .identity import infer_agent_id
from .impersonation import impersonation_dimensions
from .injection_propagation import (
    PropagationFinding,
    build_propagation_graph,
    propagation_findings,
)
from .observer import MessageEvent, MessageObserver
from .payload_injection import PayloadInjectionTracker
from .rogue import RogueFinding, detect_rogue
from .scoring import DimensionScore
from .snapshot import AgentDigest, ScanSnapshot, build_snapshot
from .topic_graph import TopicGraphBuilder

console = Console()


@dataclass(frozen=True, slots=True)
class AbfpScanResult:
    """Outcome of a single ABFP scan: rogue findings + per-agent graph metrics."""

    findings: list[RogueFinding]
    metrics: dict[str, AgentGraphMetrics]
    propagation: list[PropagationFinding] = field(default_factory=list)


def run_abfp_scan(
    target: str,
    duration: int,
    baseline_threshold: int,
    out_path: Path,
    snapshot_path: Path | None = None,
    baseline_path: Path | None = None,
) -> AbfpScanResult:
    parsed = urlparse(target)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 1883

    observer = MessageObserver()
    graph_builder = TopicGraphBuilder()
    injection_tracker = PayloadInjectionTracker()

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)

    def on_connect(c, _u, _f, _rc, _props=None):
        c.subscribe("#", qos=0)
        c.subscribe("$SYS/#", qos=0)
        console.print(f"[green][abfp] connected to {host}:{port}[/green]")

    def on_message(_c, _u, msg):
        agent_id = infer_agent_id(getattr(msg, "client_id", None), msg.topic)
        ev = MessageEvent.now(agent_id, msg.topic, msg.payload, msg.qos, bool(msg.retain))
        observer.record(ev)
        graph_builder.observe_publish(agent_id, msg.topic)
        injection_tracker.observe(agent_id, msg.topic, msg.payload)

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(host, port, keepalive=30)
    client.loop_start()
    time.sleep(duration)
    client.loop_stop()
    client.disconnect()

    bc = BaselineCollector(observer, threshold=baseline_threshold)
    current_graph = graph_builder.build()
    current_snapshot = build_snapshot(target, observer, current_graph)
    if snapshot_path is not None:
        current_snapshot.save(snapshot_path)
    metrics = all_metrics(current_graph)
    graph_block: dict[str, Any] = {
        "summary": graph_summary(current_graph),
        "agents": {aid: asdict(m) for aid, m in metrics.items()},
    }
    # Compare against a prior snapshot when given; without one, baseline == current (no drift).
    baseline = _load_baseline(baseline_path)
    baseline_graph = baseline.graph if baseline is not None else current_graph
    extra_dimensions = (
        _impersonation_dimensions(baseline.agents, current_snapshot.agents) if baseline is not None else {}
    )
    # IPI directives seen in live traffic fire regardless of baseline presence.
    for aid, dims in injection_tracker.dimensions().items():
        extra_dimensions.setdefault(aid, []).extend(dims)
    findings = detect_rogue(
        baseline_graph=baseline_graph, current_graph=current_graph, extra_dimensions=extra_dimensions
    )
    cascade = {f.agent_id: blast_radius(current_graph, f.agent_id) for f in findings}
    # Transitive IPI: reconstruct how directives propagated across agents from
    # the captured injection events, independent of baseline drift.
    propagation = propagation_findings(build_propagation_graph(injection_tracker.events()))
    _write_report(
        out_path,
        findings,
        baseline_status=bc.all_statuses(),
        target=target,
        graph=graph_block,
        cascade=cascade,
        propagation=propagation,
    )
    return AbfpScanResult(findings=findings, metrics=metrics, propagation=propagation)


def _load_baseline(baseline_path: Path | None) -> ScanSnapshot | None:
    """Load a prior snapshot when a readable path is given, else None (first-run)."""
    if baseline_path is not None and baseline_path.exists():
        return ScanSnapshot.load(baseline_path)
    return None


def _impersonation_dimensions(
    baseline_agents: dict[str, AgentDigest],
    current_agents: dict[str, AgentDigest],
) -> dict[str, list[DimensionScore]]:
    """Impersonation dimensions for agents seen in both runs that show real divergence."""
    extra: dict[str, list[DimensionScore]] = {}
    for agent_id, base in baseline_agents.items():
        current = current_agents.get(agent_id)
        if current is None:
            continue
        dims = impersonation_dimensions(base, current)
        if any(d.raw > 0.0 for d in dims):
            extra[agent_id] = dims
    return extra


def _cascade_entry(cascade: dict[str, BlastRadius] | None, agent_id: str) -> dict[str, Any] | None:
    if not cascade or agent_id not in cascade:
        return None
    br = cascade[agent_id]
    return {
        "topics": br.topics,
        "direct": br.direct,
        "transitive": br.transitive,
        "direct_count": br.direct_count,
        "transitive_count": br.transitive_count,
    }


def _propagation_block(
    propagation: list[PropagationFinding],
    cascade: dict[str, BlastRadius] | None,
) -> list[dict[str, Any]]:
    """Serialise contamination findings, fusing each target with its onward blast radius."""
    return [
        {
            "target": pf.target,
            "origin": pf.origin,
            "depth": pf.depth,
            "tier": pf.tier,
            "chain": pf.chain,
            "severity": pf.severity.value,
            "tags": list(pf.tags),
            "blast_radius": _cascade_entry(cascade, pf.target),
        }
        for pf in propagation
    ]


def _propagation_summary(propagation: list[PropagationFinding]) -> dict[str, Any]:
    """Triage header: how many agents were contaminated, how deep, from which origins."""
    return {
        "contaminated": len(propagation),
        "max_depth": max((pf.depth for pf in propagation), default=0),
        "origins": sorted({pf.origin for pf in propagation}),
    }


def _write_report(
    out_path: Path,
    findings: list[RogueFinding],
    baseline_status,
    target: str,
    graph: dict[str, Any] | None = None,
    cascade: dict[str, BlastRadius] | None = None,
    propagation: list[PropagationFinding] | None = None,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "target": target,
        "baseline": [asdict(s) for s in baseline_status],
        "findings": [
            {
                "agent_id": f.agent_id,
                "total": f.score.total,
                "severity": f.score.severity.value,
                "diff": f.diff_summary,
                "dimensions": [{"name": d.name, "raw": d.raw, "reason": d.reason} for d in f.score.dimensions],
                "blast_radius": _cascade_entry(cascade, f.agent_id),
            }
            for f in findings
        ],
    }
    if graph is not None:
        payload["graph"] = graph
    if propagation:
        payload["propagation"] = _propagation_block(propagation, cascade)
        payload["propagation_summary"] = _propagation_summary(propagation)
    out_path.write_text(json.dumps(payload, indent=2, default=str))
