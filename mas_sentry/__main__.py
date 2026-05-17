# SPDX-License-Identifier: AGPL-3.0-or-later
import click
import json
import os
from rich.console import Console
from rich.panel import Panel

console = Console()


def show_banner():
    lines = [
        "=" * 58,
        "  MAS-SENTRY-TOOLKIT  v0.1.0",
        "  Multi-Agent System Security Auditor",
        "=" * 58,
        "  ABFP  : Agent Behavioral Fingerprinting Protocol",
        "  PROTO : MQTT | AMQP",
        "  MODE  : Passive Sniff | Active Probe | STRIDE",
        "=" * 58,
        "  For authorized security testing only",
    ]
    console.print(Panel("\n".join(lines), style="bold red"))


@click.group()
@click.version_option("0.1.0")
def cli():
    """MAS-Sentry-Toolkit -- Multi-Agent System Security Auditor"""
    show_banner()


@cli.command()
@click.option("--broker",   default="127.0.0.1", show_default=True)
@click.option("--port",     default=1883,         show_default=True)
@click.option("--topic",    default="#",           show_default=True)
@click.option("--duration", default=30,            show_default=True)
@click.option("--output",   default=None)
def sniff(broker, port, topic, duration, output):
    """Passive MQTT traffic sniffer"""
    from mas_sentry.protocols.mqtt_analyzer import MQTTAnalyzer
    analyzer = MQTTAnalyzer(broker, port)
    if not analyzer.connect():
        console.print("[red]Cannot connect to broker[/red]")
        return
    msgs = analyzer.capture(duration=duration, topic_filter=topic)
    analyzer.print_topic_table()
    if output:
        data = [{"topic": m.topic, "payload": m.payload_str(),
                 "qos": m.qos, "size": m.payload_size()} for m in msgs]
        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Saved {len(msgs)} messages to {output}[/green]")
    analyzer.disconnect()


@cli.command()
@click.option("--broker",   default="127.0.0.1", show_default=True)
@click.option("--port",     default=1883,         show_default=True)
@click.option("--duration", default=60,           show_default=True)
@click.option("--output",   default="abfp_report.json", show_default=True)
def abfp(broker, port, duration, output):
    """Run ABFP behavioral fingerprinting"""
    from mas_sentry.agents.fingerprinter import ABFPFingerprinter
    from mas_sentry.agents.anomaly_detector import AnomalyDetector
    engine = ABFPFingerprinter(broker, port)
    fingerprints = engine.collect(duration=duration)
    engine.build_fingerprints()
    engine.print_summary()
    detector = AnomalyDetector()
    detector.analyze(fingerprints)
    detector.print_report(fingerprints)
    detector.save_report(output)


@cli.command()
@click.option("--broker", default="127.0.0.1", show_default=True)
@click.option("--port",   default=1883,         show_default=True)
def fingerprint(broker, port):
    """Fingerprint MQTT broker"""
    from mas_sentry.protocols.mqtt_fingerprint import MQTTBrokerFingerprinter
    from mas_sentry.protocols.mqtt_auth_check import MQTTAuthChecker
    MQTTBrokerFingerprinter(broker, port).fingerprint()
    MQTTAuthChecker(broker, port).run_all()


@cli.command()
@click.option("--broker",   default="127.0.0.1", show_default=True)
@click.option("--port",     default=1883,         show_default=True)
@click.option("--duration", default=20,           show_default=True)
def walk(broker, port, duration):
    """Walk full MQTT topic tree"""
    from mas_sentry.protocols.mqtt_topic_walker import MQTTTopicWalker
    topics = MQTTTopicWalker(broker, port).walk(duration=duration)
    console.print(f"[green]Total unique topics: {len(topics)}[/green]")


@cli.command()
@click.option("--broker",   default="127.0.0.1", show_default=True)
@click.option("--port",     default=1883,         show_default=True)
@click.option("--protocol", default="mqtt",
              type=click.Choice(["mqtt", "amqp"]), show_default=True)
@click.option("--output",   default="report.html", show_default=True)
@click.option("--full",     is_flag=True)
def audit(broker, port, protocol, output, full):
    """Run full MAS security audit"""
    from mas_sentry.protocols.mqtt_auth_check import MQTTAuthChecker
    from mas_sentry.protocols.mqtt_fingerprint import MQTTBrokerFingerprinter
    from mas_sentry.agents.fingerprinter import ABFPFingerprinter
    from mas_sentry.agents.anomaly_detector import AnomalyDetector
    from mas_sentry.threat_modeling.stride_mapper import STRIDEMapper
    from mas_sentry.reporting.report_model import MASAuditReport, ReportMeta
    from mas_sentry.reporting.html_report import HTMLReportGenerator
    import uuid
    session_id = str(uuid.uuid4())[:8]
    console.print(f"[bold green]Session {session_id} | Target: {broker}:{port}[/bold green]")
    report = MASAuditReport(meta=ReportMeta(
        session_id=session_id, target=broker, protocol=protocol))
    if protocol == "mqtt":
        MQTTBrokerFingerprinter(broker, port).fingerprint()
        auth = MQTTAuthChecker(broker, port).run_all()
        if auth.get("anonymous_access"):
            report.add_finding("Anonymous Broker Access", "CRITICAL",
                "MQTT broker allows unauthenticated connections.",
                remediation="Set allow_anonymous false in mosquitto.conf")
    duration = 60 if full else 20
    engine = ABFPFingerprinter(broker, port)
    fps = engine.collect(duration=duration)
    engine.build_fingerprints()
    detector = AnomalyDetector()
    detector.analyze(fps)
    report.abfp_fingerprints = [fp.to_dict() for fp in fps.values()]
    mapper = STRIDEMapper()
    threats = mapper.map_from_fingerprints(fps)
    report.stride_threats = [t.to_dict() for t in threats]
    os.makedirs("reports", exist_ok=True)
    out = f"reports/{output}"
    HTMLReportGenerator(report).save(out)
    report.save_json(out.replace(".html", ".json"))
    console.print(f"[bold green]Done! Report: {out}[/bold green]")



@cli.command()
@click.option("--broker",   default="127.0.0.1", show_default=True)
@click.option("--port",     default=1883,         show_default=True)
@click.option("--topics",   default="commands/#,sensors/#", show_default=True)
def probe(broker, port, topics):
    """Active probe - inject crafted messages, detect reactions"""
    from mas_sentry.agents.active_prober import ActiveProber
    topic_list = [t.strip() for t in topics.split(",")]
    prober = ActiveProber(broker, port)
    prober.probe_command_injection(topic_list)
    prober.probe_retained_state(topic_list)
    prober.print_results()



@cli.command()
@click.option("--broker",   default="127.0.0.1", show_default=True)
@click.option("--port",     default=1883,         show_default=True)
@click.option("--duration", default=60,           show_default=True)
@click.option("--output",   default="baseline.json", show_default=True)
def learn(broker, port, duration, output):
    """Learn normal agent behavior and save baseline"""
    from mas_sentry.agents.fingerprinter import ABFPFingerprinter
    from mas_sentry.agents.abfp_models import BehavioralBaseline
    import json, os
    engine = ABFPFingerprinter(broker, port)
    fps = engine.collect(duration=duration)
    engine.build_fingerprints()
    baselines = {}
    for agent_id, fp in fps.items():
        bl = BehavioralBaseline(
            agent_id=agent_id,
            known_topics=fp.unique_topics,
            expected_interval_ms=fp.timing.mean_interval_ms,
            expected_payload_size=fp.payload.mean_size_bytes,
            expected_entropy=fp.payload.entropy_score
        )
        baselines[agent_id] = bl.save.__func__
    os.makedirs("reports", exist_ok=True)
    data = {}
    for agent_id, fp in fps.items():
        data[agent_id] = {
            "known_topics": fp.unique_topics,
            "expected_interval_ms": fp.timing.mean_interval_ms,
            "expected_payload_size": fp.payload.mean_size_bytes,
            "expected_entropy": fp.payload.entropy_score
        }
    with open(output, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[bold green]Baseline saved: {output} ({len(data)} agents)[/bold green]")


if __name__ == "__main__":
    cli()


@cli.command()
@click.option("--output", "-o", default=".", help="Output directory for reports")
@click.option("--format", "-f",
              type=click.Choice(["json", "html", "markdown"]),
              default="json", show_default=True,
              help="Report output format")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
def config(output: str, format: str, verbose: bool):
    """Show current configuration and output settings."""
    from rich.table import Table
    from rich.console import Console

    console = Console()
    table = Table(title="MAS-Sentry Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Output Directory", output)
    table.add_row("Report Format", format)
    table.add_row("Verbose Mode", str(verbose))
    table.add_row("Version", "0.9.0")

    console.print(table)
