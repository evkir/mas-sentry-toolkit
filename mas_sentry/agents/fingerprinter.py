# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ABFPFingerprinter — Phase 1 & 2 implementation.
Passive collection + fingerprint construction.
"""

import math
import time

import paho.mqtt.client as mqtt
from rich.console import Console
from rich.table import Table

from .abfp_models import AgentFingerprint, MessageEvent, PayloadMetrics, TimingMetrics, TopicProfile
from .payload_analyzer import detect_encoding, shannon_entropy

console = Console()


class ABFPFingerprinter:
    """
    ABFP Phase 1: Passive behavioral data collection.
    ABFP Phase 2: Fingerprint construction from collected data.

    Infers agent identity from topic naming patterns:
      sensors/sensor_001/telemetry → agent_id: inferred_sensors_sensor_001
    """

    MIN_MESSAGES_FOR_CONFIDENCE = 10

    def __init__(self, host: str, port: int = 1883):
        self.host = host
        self.port = port
        self.fingerprints: dict[str, AgentFingerprint] = {}
        self._total_messages = 0

    def _infer_agent_id(self, topic: str) -> str:
        parts = topic.split("/")
        if len(parts) >= 2:
            return f"inferred_{parts[0]}_{parts[1]}"
        return f"inferred_{parts[0]}"

    def _get_or_create(self, agent_id: str, now: float) -> AgentFingerprint:
        if agent_id not in self.fingerprints:
            self.fingerprints[agent_id] = AgentFingerprint(agent_id=agent_id, first_seen=now, last_seen=now)
            console.print(f"[cyan][ABFP] New agent discovered: {agent_id}[/cyan]")
        return self.fingerprints[agent_id]

    def collect(self, duration: int = 60, topic_filter: str = "#") -> dict[str, AgentFingerprint]:
        """Phase 1: Passive collection"""
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="mas-sentry-abfp")

        def on_message(c, u, msg):
            now = time.time()
            agent_id = self._infer_agent_id(msg.topic)
            fp = self._get_or_create(agent_id, now)
            fp.last_seen = now

            # Update topic profile
            if msg.topic not in fp.topic_profiles:
                fp.topic_profiles[msg.topic] = TopicProfile(topic=msg.topic, first_seen=now)
            tp = fp.topic_profiles[msg.topic]
            tp.message_count += 1
            tp.total_bytes += len(msg.payload)
            tp.last_seen = now
            tp.qos_levels.append(msg.qos)
            if msg.retain:
                tp.retain_count += 1

            # Store event
            preview = msg.payload.decode("utf-8", errors="replace")[:40]
            fp.message_events.append(
                MessageEvent(
                    topic=msg.topic,
                    payload_size=len(msg.payload),
                    timestamp=now,
                    qos=msg.qos,
                    retain=bool(msg.retain),
                    payload_preview=preview,
                )
            )
            self._total_messages += 1

        def on_connect(c, u, f, rc, properties=None):
            if rc == 0:
                c.subscribe(topic_filter, qos=0)
                console.print(
                    f"[bold green][ABFP] Phase 1 started — collecting for {duration}s on '{topic_filter}'[/bold green]"
                )

        client.on_message = on_message
        client.on_connect = on_connect
        client.connect(self.host, self.port)
        client.loop_start()

        start = time.time()
        while time.time() - start < duration:
            elapsed = int(time.time() - start)
            agents = len(self.fingerprints)
            msgs = self._total_messages
            print(f"\r[ABFP] {elapsed}s | {agents} agents | {msgs} messages    ", end="")
            time.sleep(1)

        client.loop_stop()
        client.disconnect()
        print()
        console.print(
            f"[bold green][ABFP] Phase 1 complete: "
            f"{len(self.fingerprints)} agents, "
            f"{self._total_messages} messages[/bold green]"
        )
        return self.fingerprints

    def build_fingerprints(self) -> dict[str, AgentFingerprint]:
        """Phase 2: Compute all metrics for each collected agent"""
        console.print("[bold cyan][ABFP] Phase 2 — Building fingerprints...[/bold cyan]")

        for agent_id, fp in self.fingerprints.items():
            self._compute_timing(fp)
            self._compute_payload(fp)
            self._compute_confidence(fp)
            console.print(
                f"[green][ABFP] {agent_id}: "
                f"{fp.message_count} msgs | "
                f"interval={fp.timing.mean_interval_ms:.0f}ms | "
                f"entropy={fp.payload.entropy_score:.2f} | "
                f"confidence={fp.confidence:.2f}[/green]"
            )
        return self.fingerprints

    def _compute_timing(self, fp: AgentFingerprint):
        events = sorted(fp.message_events, key=lambda e: e.timestamp)
        if len(events) < 2:
            return
        intervals = [(events[i + 1].timestamp - events[i].timestamp) * 1000 for i in range(len(events) - 1)]
        n = len(intervals)
        mean = sum(intervals) / n
        variance = sum((x - mean) ** 2 for x in intervals) / n
        std = math.sqrt(variance)

        fp.timing = TimingMetrics(
            mean_interval_ms=mean,
            std_interval_ms=std,
            min_interval_ms=min(intervals),
            max_interval_ms=max(intervals),
            burst_detected=min(intervals) < 50.0,
            sample_count=n,
        )

    def _compute_payload(self, fp: AgentFingerprint):
        if not fp.message_events:
            return
        sizes = [e.payload_size for e in fp.message_events]
        n = len(sizes)
        mean = sum(sizes) / n
        variance = sum((x - mean) ** 2 for x in sizes) / n
        std = math.sqrt(variance)

        # Entropy from last payload sample
        last_events = fp.message_events[-min(10, n) :]
        all_bytes = b""
        for ev in last_events:
            # Reconstruct from preview only (real impl uses raw bytes)
            all_bytes += ev.payload_preview.encode("utf-8", errors="replace")
        entropy = shannon_entropy(all_bytes)

        # Encoding from last event preview
        encoding = detect_encoding(fp.message_events[-1].payload_preview.encode("utf-8", errors="replace"))

        fp.payload = PayloadMetrics(
            mean_size_bytes=mean,
            std_size_bytes=std,
            min_size_bytes=min(sizes),
            max_size_bytes=max(sizes),
            entropy_score=entropy,
            encoding=encoding,
        )

    def _compute_confidence(self, fp: AgentFingerprint):
        count = fp.message_count
        if count >= 50:
            fp.confidence = 1.0
        elif count >= self.MIN_MESSAGES_FOR_CONFIDENCE:
            fp.confidence = count / 50.0
        else:
            fp.confidence = count / self.MIN_MESSAGES_FOR_CONFIDENCE * 0.5

    def print_summary(self):
        """Print rich fingerprint summary table"""
        table = Table(title="[bold red]ABFP Fingerprint Summary[/bold red]")
        table.add_column("Agent ID", style="cyan")
        table.add_column("Messages", justify="right")
        table.add_column("Topics", justify="right")
        table.add_column("Interval ms", justify="right", style="yellow")
        table.add_column("Entropy", justify="right", style="magenta")
        table.add_column("Confidence", justify="right", style="green")
        table.add_column("Flags", style="red")

        for agent_id, fp in self.fingerprints.items():
            table.add_row(
                agent_id,
                str(fp.message_count),
                str(len(fp.unique_topics)),
                f"{fp.timing.mean_interval_ms:.0f}",
                f"{fp.payload.entropy_score:.2f}",
                f"{fp.confidence:.2f}",
                ", ".join(fp.threat_flags) or "—",
            )
        console.print(table)
