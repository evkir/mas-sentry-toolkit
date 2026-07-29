# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit the content of retained MQTT messages, not merely their topic names.

The topic walk reported which topics exist. What sits inside a retained message
went unread, and retained state is the wrong content to skip: the broker stores
one retained message per topic and hands it to every client the moment it
subscribes. No agent asks for it and no agent can decline it - it arrives with
the subscription.

That makes a poisoned retained message the MQTT twin of a poisoned MCP resource,
with two differences that both favour the attacker. It persists without the
attacker staying connected, since the broker holds it until someone overwrites
it. And it is delivered on subscribe rather than on request, so it reaches every
agent that reconnects, including agents that join long after the attacker left.

Content is checked on the same two axes the MCP resource audit uses, through the
same core primitives: directives arriving inside the data (the ingestion half)
via injection_scan, and auto-fetch beacons embedded in it (the leak half) via
output_exfil.

Scope note: this audit only reads. Establishing that an attacker could plant a
retained message means publishing one, which writes to the target broker, so it
is not done here.
"""

from __future__ import annotations

from mas_sentry.core.finding import Finding, Severity
from mas_sentry.core.injection_scan import STRONG_PATTERNS, scan_string
from mas_sentry.core.output_exfil import scan_exfiltration_channels

# Retained payloads are normally small control or config blobs. The cap keeps one
# oversized payload from stalling a sweep; directives and beacons are inline
# constructs, so a generous prefix finds them.
MAX_SCAN_CHARS = 20000
# Payload excerpt carried as evidence, enough to recognise the message.
_SAMPLE_CHARS = 200

_TAGS_INJECTION = ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Tampering", "AML.T0051"]
_TAGS_EXFIL = ["ASI01_Goal_Hijack", "CWE-1427", "STRIDE_Information_Disclosure"]


def audit_retained(retained: dict[str, str], target: str) -> list[Finding]:
    """Findings for retained payloads carrying injection directives or beacons.

    Emits the unified Finding directly: an intermediate row type would need an
    adapter, and an adapter is the thing that historically got written and never
    called.
    """
    findings: list[Finding] = []
    for topic in sorted(retained):
        body = retained[topic][:MAX_SCAN_CHARS]
        matches = scan_string(body)
        if matches:
            patterns = [m.pattern for m in matches]
            strong = [p for p in patterns if p in STRONG_PATTERNS]
            findings.append(
                Finding(
                    module="mqtt.retained_injection",
                    title=f"Retained message carries injection directives: {topic}",
                    detail=(
                        f"The retained payload on {topic} contains {', '.join(patterns)}. "
                        "The broker replays this message to every client the moment it subscribes, "
                        "so any agent that reconnects ingests the directive without requesting it, "
                        "and it keeps doing so until someone overwrites the topic."
                    ),
                    # A strong pattern is an explicit control-flow takeover or is
                    # hidden from human review; the ambient patterns alone are
                    # suggestive but appear in benign operational text too.
                    severity=Severity.HIGH if strong else Severity.MEDIUM,
                    target=target,
                    tags=["mqtt", *_TAGS_INJECTION],
                    evidence={
                        "topic": topic,
                        "patterns": patterns,
                        "strong_patterns": strong,
                        "sample": body[:_SAMPLE_CHARS],
                    },
                )
            )
        channels = scan_exfiltration_channels(body)
        if channels:
            findings.append(
                Finding(
                    module="mqtt.retained_exfil",
                    title=f"Retained message embeds an auto-fetch beacon: {topic}",
                    detail=(
                        f"The retained payload on {topic} embeds {len(channels)} auto-fetch "
                        f"channel(s): {', '.join(sorted({c.url for c in channels}))}. A client that "
                        "renders this content reaches out to the URL on its own, which turns a "
                        "message every subscriber receives into a callback the attacker observes."
                    ),
                    severity=Severity.HIGH,
                    target=target,
                    tags=["mqtt", *_TAGS_EXFIL],
                    evidence={
                        "topic": topic,
                        "channels": [{"kind": c.kind, "url": c.url} for c in channels],
                        "sample": body[:_SAMPLE_CHARS],
                    },
                )
            )
    return findings


def retained_inventory(retained: dict[str, str], target: str) -> Finding:
    """One INFO row recording the persistent state a subscriber was handed."""
    topics = sorted(retained)
    noun = "message" if len(topics) == 1 else "messages"
    return Finding(
        module="mqtt.retained_state",
        title=f"Retained state: {len(topics)} {noun}",
        detail=(
            f"{len(topics)} retained {noun} were delivered on subscribe: {', '.join(topics[:12])}. "
            "Retained messages persist on the broker and are replayed to every new subscriber, so "
            "they are the broker durable memory rather than transient traffic."
            if topics
            else "No retained messages were delivered on subscribe."
        ),
        severity=Severity.INFO,
        target=target,
        tags=["mqtt"],
        evidence={"topics": topics[:25], "count": len(topics)},
    )
