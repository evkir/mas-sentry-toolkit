# SPDX-License-Identifier: AGPL-3.0-or-later
"""MQTT broker audit orchestrator.

The MQTT probes in this package have existed since before the pivot and are
covered by unit tests, but nothing in the product ever called them: no CLI
command imported them and no adapter mapped their output, so a broker audit
could not produce a single reportable finding. This module is the missing
middle - it drives the probes and emits the unified `Finding` directly.

Emitting `Finding` rather than a private dict shape is deliberate. Every scan
surface that invented its own row format needed an adapter later, and the MCP
adapter written for exactly that reason sat unused in the product while every
MCP finding reached the reports as module "unknown". A new surface that speaks
the shared vocabulary from the start cannot repeat that.

Three judgement calls, each settled against a live Mosquitto rather than by
reasoning about the protocol:

- A broker allowing anonymous access accepts *any* credential pair, so the
  guest/guest and admin/admin probes both succeed against it. Reporting those
  as separate default-credential findings yields two HIGH false positives on
  every open broker. They are folded into one INFO note that explains why they
  are not separately assessable.
- An accepted wildcard subscription is not evidence of read access. Mosquitto
  answers a '#' SUBSCRIBE with "Granted QoS 0" even when its ACL forbids the
  topics, then silently declines to deliver them: in the rig, SUBACK was granted
  and only the one ACL-permitted topic arrived. The exposure finding is therefore
  keyed on messages actually delivered, not on the subscription being accepted.
- A probe that could not run is reported, never dropped. A refusal from a broker
  that enforces authentication is expected and lands as INFO; an unreachable
  broker is a real coverage gap and lands as MEDIUM. An audit that reached no
  broker must not read like an audit that found nothing wrong.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mas_sentry.core.audit_log import write as audit_write
from mas_sentry.core.finding import Finding, Severity
from mas_sentry.core.scope import assert_in_scope
from mas_sentry.protocols.mqtt_auth_check import MQTTAuthChecker
from mas_sentry.protocols.mqtt_connect import BrokerRefusedConnection, BrokerUnreachable
from mas_sentry.protocols.mqtt_fingerprint import MQTTBrokerFingerprinter
from mas_sentry.protocols.mqtt_retained_audit import audit_retained, retained_inventory
from mas_sentry.protocols.mqtt_topic_walker import MQTTTopicWalker
from mas_sentry.reporting.structured import write_json

ALL_CHECKS = ("auth", "fingerprint", "topics", "retained")
DEFAULT_PORT = 1883
# Topic names carried in evidence. The report is for a human deciding where to
# look next, so the inventory is sampled rather than dumped whole.
TOPIC_SAMPLE = 25

# $SYS counters an anonymous reader should not be handed: they name the broker
# build for CVE lookup and expose live client counts and message rates.
_SYS_KEYS = ("version", "uptime", "clients_connected", "messages_received")

_TAGS_ANON = ["ASI03_Identity_Abuse", "CWE-306", "STRIDE_Spoofing"]
_TAGS_DEFAULT_CREDS = ["ASI03_Identity_Abuse", "CWE-1392", "STRIDE_Spoofing"]
_TAGS_EXPOSURE = ["ASI03_Identity_Abuse", "CWE-306", "STRIDE_Information_Disclosure"]
_TAGS_SYS = ["CWE-200", "STRIDE_Information_Disclosure"]

_DEFAULT_CRED_LABELS = {
    "default_guest": "guest:guest",
    "default_admin": "admin:admin",
}


def _gap(target: str, probe: str, reason: str, severity: Severity) -> Finding:
    """A probe that did not run, recorded as a gap rather than a silent absence."""
    return Finding(
        module="mqtt.enumeration_gap",
        title=f"{probe}: not assessed ({reason})",
        detail=(
            f"The {probe} probe could not run against {target}: {reason}. "
            "This is not evidence of a secure broker - the surface was never reached, "
            "so treat it as unassessed."
        ),
        severity=severity,
        target=target,
        tags=["mqtt", "enumeration_gap"],
        evidence={"probe": probe, "reason": reason},
    )


def _refusal_gap(target: str, probe: str, exc: BrokerRefusedConnection) -> Finding:
    """A broker that answers and rejects us has enforced authentication.

    That is the outcome we want from a broker, so it is not a MEDIUM problem -
    but the surface behind the credential wall stays unexamined, and the report
    has to say so rather than imply the probe came back clean.
    """
    return _gap(target, probe, f"broker refused the connection ({exc.reason})", Severity.INFO)


def _auth_findings(target: str, results: dict[str, bool]) -> list[Finding]:
    """Turn the credential probe results into findings."""
    anon = results.get("anonymous_access", False)
    out: list[Finding] = []
    if anon:
        out.append(
            Finding(
                module="mqtt.anonymous_access",
                title="Broker accepts anonymous connections",
                detail=(
                    f"{target} accepted a CONNECT with no credentials. Any host that can reach "
                    "the broker can subscribe to agent traffic and publish into it."
                ),
                severity=Severity.CRITICAL,
                target=target,
                tags=["mqtt", *_TAGS_ANON],
                evidence={"anonymous_access": True},
            )
        )
        accepted = [label for key, label in _DEFAULT_CRED_LABELS.items() if results.get(key)]
        if accepted:
            out.append(
                Finding(
                    module="mqtt.default_credentials",
                    title="Default credentials not separately assessable",
                    detail=(
                        f"{', '.join(accepted)} were accepted, but so is any other pair: the broker "
                        "allows anonymous access, so it does not evaluate credentials at all. This is "
                        "the same weakness already reported above, not an additional one."
                    ),
                    severity=Severity.INFO,
                    target=target,
                    tags=["mqtt"],
                    evidence={"accepted": accepted, "anonymous_access": True},
                )
            )
        return out

    for key, label in _DEFAULT_CRED_LABELS.items():
        if results.get(key):
            out.append(
                Finding(
                    module="mqtt.default_credentials",
                    title=f"Default credentials accepted: {label}",
                    detail=(
                        f"{target} enforces authentication but accepted {label}. The credential pair "
                        "is a documented default and is tried first by any commodity scanner."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    tags=["mqtt", *_TAGS_DEFAULT_CREDS],
                    evidence={"credentials": label},
                )
            )
    if not out:
        out.append(
            Finding(
                module="mqtt.auth",
                title="Authentication enforced",
                detail=f"{target} refused anonymous access and both default credential pairs.",
                severity=Severity.INFO,
                target=target,
                tags=["mqtt"],
                evidence=dict(results),
            )
        )
    return out


def _fingerprint_findings(target: str, info: dict[str, Any]) -> list[Finding]:
    """Broker identity, plus the $SYS exposure that produced it."""
    broker = str(info.get("broker_type", "unknown"))
    version = str(info.get("version", "unknown"))
    out = [
        Finding(
            module="mqtt.fingerprint",
            title=f"Broker: {broker}",
            detail=f"{target} identifies as {broker}, version string: {version}.",
            severity=Severity.INFO,
            target=target,
            tags=["mqtt"],
            evidence={k: info.get(k) for k in _SYS_KEYS},
        )
    ]
    sys_count = int(info.get("sys_topics_count", 0) or 0)
    if sys_count:
        out.append(
            Finding(
                module="mqtt.sys_exposure",
                title=f"$SYS tree readable without credentials ({sys_count} topics)",
                detail=(
                    f"{target} served {sys_count} $SYS topics to an unauthenticated subscriber, "
                    f"including the broker version ({version}) and live client and message counters. "
                    "That is the version string an attacker needs to select a broker CVE, and a "
                    "running count of how many agents are attached."
                ),
                severity=Severity.MEDIUM,
                target=target,
                tags=["mqtt", *_TAGS_SYS],
                evidence={"sys_topics_count": sys_count, **{k: info.get(k) for k in _SYS_KEYS}},
            )
        )
    return out


def _topic_findings(target: str, topics: list[str], duration: int, anonymous: bool) -> list[Finding]:
    """The inventory, and the exposure only delivered traffic can establish."""
    noun = "topic" if len(topics) == 1 else "topics"
    detail = (
        f"{len(topics)} distinct topics observed in {duration}s: {', '.join(topics[:12])}"
        if topics
        else (
            f"No traffic reached the subscriber in {duration}s. The subscription was accepted, but "
            "acceptance alone does not mean the broker would have delivered anything: a topic ACL "
            "grants the subscription and then withholds the messages. Either the broker was idle or "
            "its ACL withheld the traffic; a longer --duration distinguishes the two."
        )
    )
    out = [
        Finding(
            module="mqtt.topic_inventory",
            title=f"Topic inventory: {len(topics)} {noun}",
            detail=detail,
            severity=Severity.INFO,
            target=target,
            tags=["mqtt"],
            evidence={"topics": topics[:TOPIC_SAMPLE], "count": len(topics), "duration_s": duration},
        )
    ]
    if anonymous and topics:
        out.append(
            Finding(
                module="mqtt.topic_exposure",
                title=f"Live agent traffic readable without credentials ({len(topics)} {noun})",
                detail=(
                    "A wildcard subscriber presenting no credentials received live message traffic. "
                    "This is the read half of a man-in-the-middle position over the agent mesh, and "
                    "unlike an accepted subscription it is proof: the messages arrived."
                ),
                severity=Severity.HIGH,
                target=target,
                tags=["mqtt", *_TAGS_EXPOSURE],
                evidence={"topics": topics[:TOPIC_SAMPLE], "count": len(topics)},
            )
        )
    return out


def run_mqtt_scan(
    host: str,
    port: int = DEFAULT_PORT,
    checks: str = "all",
    duration: int = 20,
    out: Path = Path("reports/mqtt.json"),
    scope_confirmed: bool = False,
) -> list[Finding]:
    """Audit an MQTT broker and write unified Findings to `out`.

    `checks` is "all" or a comma-separated subset of auth, fingerprint, topics.
    The credential probe runs first because whether the broker accepts anonymous
    connections decides how the rest of the results should be read - an exposed
    topic inventory means something different on a broker that asked for a
    password.
    """
    target = f"{host}:{port}"
    assert_in_scope(host, confirmed=scope_confirmed)
    selected = ALL_CHECKS if checks == "all" else tuple(c.strip() for c in checks.split(","))
    audit_write({"action": "mqtt_scan_start", "target": target, "checks": checks})

    findings: list[Finding] = []
    anonymous = False

    if "auth" in selected:
        try:
            results = MQTTAuthChecker(host, port, confirmed=scope_confirmed).run_all()
            anonymous = bool(results.get("anonymous_access"))
            findings.extend(_auth_findings(target, results))
        except BrokerUnreachable as exc:
            findings.append(_gap(target, "auth", str(exc), Severity.MEDIUM))

    if "fingerprint" in selected:
        try:
            info = MQTTBrokerFingerprinter(host, port, confirmed=scope_confirmed).fingerprint()
            findings.extend(_fingerprint_findings(target, info))
        except BrokerRefusedConnection as exc:
            findings.append(_refusal_gap(target, "fingerprint", exc))
        except BrokerUnreachable as exc:
            findings.append(_gap(target, "fingerprint", str(exc), Severity.MEDIUM))

    if "topics" in selected or "retained" in selected:
        # One walk serves both checks: retained messages arrive on the same
        # wildcard subscription, so collecting them costs no second connection.
        walker = MQTTTopicWalker(host, port, confirmed=scope_confirmed)
        try:
            topics = walker.walk(duration=duration)
            if "topics" in selected:
                findings.extend(_topic_findings(target, topics, duration, anonymous))
            if "retained" in selected:
                findings.append(retained_inventory(walker.retained, target))
                findings.extend(audit_retained(walker.retained, target))
        except BrokerRefusedConnection as exc:
            findings.append(_refusal_gap(target, "topic_walk", exc))
        except BrokerUnreachable as exc:
            findings.append(_gap(target, "topic_walk", str(exc), Severity.MEDIUM))

    out.parent.mkdir(parents=True, exist_ok=True)
    write_json(findings, target, out)
    audit_write({"action": "mqtt_scan_done", "target": target, "findings": len(findings)})
    return findings


def parse_target(target: str) -> tuple[str, int]:
    """Accept mqtt://host:port, host:port or a bare host. Default port 1883."""
    rest = target.split("://", 1)[1] if "://" in target else target
    rest = rest.rstrip("/")
    if not rest:
        raise ValueError("empty MQTT target")
    if rest.startswith("["):  # bracketed IPv6, optionally followed by :port
        closing = rest.find("]")
        if closing == -1:
            raise ValueError(f"unterminated IPv6 literal: {target}")
        host = rest[1:closing]
        tail = rest[closing + 1 :]
        port_part = tail[1:] if tail.startswith(":") else ""
    elif rest.count(":") == 1:
        host, _, port_part = rest.partition(":")
    else:  # bare host, or an unbracketed IPv6 literal
        host, port_part = rest, ""
    if not host:
        raise ValueError(f"no host in MQTT target: {target}")
    if not port_part:
        return host, DEFAULT_PORT
    try:
        port = int(port_part)
    except ValueError as exc:
        raise ValueError(f"invalid port in MQTT target: {target}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range in MQTT target: {target}")
    return host, port
