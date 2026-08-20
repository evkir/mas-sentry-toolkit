# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit a RabbitMQ management API and return Findings.

The analyzer this drives has always worked - it was simply unreachable from
the CLI and printed tables instead of returning anything, so nothing it saw
could reach `report convert`. A finding a human has to read off a terminal is
a finding that does not exist by the time the engagement is written up.

Two honesty notes that shape the severities here. The port audited is 15672,
the management HTTP API, not 5672: this module has never spoken AMQP and
saying so is cheaper than implying otherwise. And RabbitMQ refuses the `guest`
account from anything but loopback by default, so a remote run that fails to
authenticate as guest has not shown that guest is absent - it has shown that
this vantage point cannot use it. That distinction is carried in the finding
rather than resolved by guesswork.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mas_sentry.core.audit_log import write as audit_write
from mas_sentry.core.finding import Finding, Severity
from mas_sentry.core.scope import assert_in_scope
from mas_sentry.protocols.amqp_analyzer import AMQPAnalyzer
from mas_sentry.reporting.structured import write_json

DEFAULT_MGMT_PORT = 15672
# The exchange the tracing plugin publishes every seen message to. A binding
# from it to a durable queue is a full-fidelity copy of the traffic.
TRACE_EXCHANGE = "amq.rabbitmq.trace"
# Names carried into evidence. The report is for a human deciding where to look
# next, so the inventory is sampled rather than dumped whole.
NAME_SAMPLE = 25

_TAGS_DEFAULT_CREDS = ["amqp", "ASI03_Identity_Abuse", "CWE-1392", "STRIDE_Spoofing"]
_TAGS_TRACE = ["amqp", "CWE-200", "STRIDE_Information_Disclosure"]


def parse_target(target: str) -> tuple[str, int]:
    """Accept amqp://host:port, http://host:port, host:port or a bare host.

    The port is the management port, not the AMQP one: 5672 answers a binary
    protocol this module does not speak, and silently auditing a different port
    than the one the operator typed would be worse than asking.
    """
    rest = target.split("://", 1)[1] if "://" in target else target
    rest = rest.rstrip("/")
    if not rest:
        raise ValueError("empty AMQP target")
    if rest.startswith("["):
        closing = rest.find("]")
        if closing == -1:
            raise ValueError(f"unterminated IPv6 literal: {target}")
        host = rest[1:closing]
        tail = rest[closing + 1 :]
        port_part = tail[1:] if tail.startswith(":") else ""
    elif rest.count(":") == 1:
        host, _, port_part = rest.partition(":")
    else:
        host, port_part = rest, ""
    if not host:
        raise ValueError(f"no host in AMQP target: {target}")
    if not port_part:
        return host, DEFAULT_MGMT_PORT
    try:
        port = int(port_part)
    except ValueError as exc:
        raise ValueError(f"invalid port in AMQP target: {target}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range in AMQP target: {target}")
    return host, port


def _names(items: list[dict[str, Any]]) -> list[str]:
    return [str(i.get("name") or "[default]") for i in items[:NAME_SAMPLE]]


def _gap(target: str, detail: str) -> Finding:
    return Finding(
        module="amqp.management",
        title="Management API not assessed",
        detail=detail,
        severity=Severity.MEDIUM,
        target=target,
        tags=["amqp", "enumeration_gap"],
        evidence={"reachable": False},
    )


def _credential_finding(target: str, guest_works: bool, host: str) -> Finding:
    if guest_works:
        return Finding(
            module="amqp.management",
            title="Management API accepts the default guest account",
            detail=(
                "guest:guest authenticated against the management API. RabbitMQ restricts that account "
                "to loopback out of the box, so reaching it from anywhere else means the restriction was "
                "lifted and the broker is administrable by anyone who can route to the port."
            ),
            severity=Severity.CRITICAL,
            target=target,
            tags=list(_TAGS_DEFAULT_CREDS),
            evidence={"account": "guest", "host": host},
        )
    return Finding(
        module="amqp.management",
        title="Default guest account not usable from here",
        detail=(
            "guest:guest was refused from this vantage point. That is not proof the account is gone: "
            "RabbitMQ refuses guest from anything but loopback by default, so the same account may still "
            "work for anything running on the broker host."
        ),
        severity=Severity.INFO,
        target=target,
        tags=["amqp"],
        evidence={"account": "guest", "host": host},
    )


def _trace_findings(target: str, bindings: list[dict[str, Any]]) -> list[Finding]:
    traced = [b for b in bindings if b.get("source") == TRACE_EXCHANGE]
    if not traced:
        return []
    sinks = sorted({str(b.get("destination", "?")) for b in traced})
    return [
        Finding(
            module="amqp.management",
            title=f"Message tracing is wired into {len(sinks)} queue(s)",
            detail=(
                f"Bindings from {TRACE_EXCHANGE} deliver a copy of every traced message - headers and "
                f"body - to {', '.join(sinks[:NAME_SAMPLE])}. Anything an agent publishes through a traced "
                "exchange is readable by whoever can drain those queues."
            ),
            severity=Severity.HIGH,
            target=target,
            tags=list(_TAGS_TRACE),
            evidence={"sinks": sinks[:NAME_SAMPLE], "bindings": len(traced)},
        )
    ]


def _inventory_finding(
    target: str,
    exchanges: list[dict[str, Any]],
    queues: list[dict[str, Any]],
    connections: list[dict[str, Any]],
) -> Finding:
    idle = [str(q.get("name", "?")) for q in queues if q.get("messages", 0) and not q.get("consumers", 0)]
    return Finding(
        module="amqp.management",
        title=(f"Topology readable: {len(exchanges)} exchanges, {len(queues)} queues, {len(connections)} connections"),
        detail=(
            "The management API handed over the broker topology to the account used for this scan. "
            "Queue and exchange names describe what the agents talk about, which is the map an attacker "
            "would otherwise have to guess at."
        ),
        severity=Severity.INFO,
        target=target,
        tags=["amqp"],
        evidence={
            "exchanges": _names(exchanges),
            "queues": _names(queues),
            "queues_with_backlog_and_no_consumer": idle[:NAME_SAMPLE],
            "connections": len(connections),
        },
    )


def run_amqp_scan(
    host: str,
    mgmt_port: int = DEFAULT_MGMT_PORT,
    username: str = "guest",
    password: str = "guest",
    vhost: str = "%2F",
    out: Path = Path("reports/amqp.json"),
    scope_confirmed: bool = False,
) -> list[Finding]:
    """Audit the management API and write unified Findings to `out`."""
    target = f"{host}:{mgmt_port}"
    assert_in_scope(host, confirmed=scope_confirmed)
    audit_write({"action": "amqp_scan_start", "target": target, "username": username})

    analyzer = AMQPAnalyzer(host, username=username, password=password, mgmt_port=mgmt_port, vhost=vhost)
    findings: list[Finding] = []

    if not analyzer.connect():
        findings.append(
            _gap(
                target,
                f"The management API at {target} did not answer, or refused the credentials offered. "
                "Nothing below was established - this is a gap in the scan, not a clean result.",
            )
        )
    else:
        findings.append(_credential_finding(target, analyzer.check_default_credentials(), host))
        exchanges = analyzer.enumerate_exchanges()
        queues = analyzer.enumerate_queues()
        connections = analyzer.enumerate_connections()
        findings.extend(_trace_findings(target, analyzer.enumerate_bindings()))
        findings.append(_inventory_finding(target, exchanges, queues, connections))

    out.parent.mkdir(parents=True, exist_ok=True)
    write_json(findings, target, out)
    audit_write({"action": "amqp_scan_done", "target": target, "findings": len(findings)})
    return findings
