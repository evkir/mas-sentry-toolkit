# SPDX-License-Identifier: AGPL-3.0-or-later
"""Audit the content of MCP resources, not merely their listing.

MST enumerated resources and never read one, so their contents were the only
agent-facing MCP surface that went entirely unaudited. That is the wrong surface
to skip: resources are exactly what an agent pulls into context on its own
initiative, which makes a poisoned resource the textbook indirect-injection
vector - the instruction does not come from the user, it arrives with data the
agent fetched and trusted.

Reading is safe to do here in a way that calling arbitrary tools is not.
`resources/read` is defined as returning application-controlled data, so it
carries no side effects by design, whereas invoking an unknown tool could write,
delete or spend. This audit therefore reads what a client would read and nothing
more.

Each resource is checked on two axes with the shared core primitives: hidden
directives arriving in the content (the cause) via injection_scan, and
auto-fetch exfiltration beacons embedded in it (the effect) via output_exfil. A
resource carrying a beacon leaks on render, exactly the EchoLeak pattern, and a
resource carrying a directive is the ingestion half of the same attack.
"""

from __future__ import annotations

from dataclasses import dataclass

from mas_sentry.core.injection_scan import STRONG_PATTERNS, scan_string
from mas_sentry.core.output_exfil import scan_exfiltration_channels

from ..client import McpClient, ResourceTemplateDef
from ..content import extract_block_text, is_tool_error

# Resource bodies can be whole documents; cap the scan so one oversized payload
# cannot stall a sweep. Directives and beacons are inline constructs, so a
# generous prefix is enough to find them.
_MAX_SCAN_CHARS = 20000


@dataclass(frozen=True, slots=True)
class ResourceFinding:
    """One resource whose content carries injection or exfiltration signal."""

    uri: str
    injection_patterns: tuple[str, ...] = ()
    exfil_channels: tuple[str, ...] = ()
    sample: str = ""

    @property
    def severity(self) -> str:
        """HIGH only for unambiguous signal; weaker matches stay MEDIUM.

        A strong injection pattern (invisible characters, an explicit override,
        a tool-call hijack) is not something benign content contains by
        accident. An external auto-fetch beacon is likewise concrete. Softer
        phrasing matches alone are a lead, not a verdict.
        """
        if self.exfil_channels or any(p in STRONG_PATTERNS for p in self.injection_patterns):
            return "HIGH"
        return "MEDIUM"


def _read_resource_text(client: McpClient, uri: str) -> str:
    """Fetch one resource and return its decoded text, or empty on refusal."""
    resp = client.send("resources/read", {"uri": uri})
    if resp.is_error or is_tool_error(resp.result):
        return ""
    result = resp.result
    if not isinstance(result, dict):
        return ""
    contents = result.get("contents")
    if not isinstance(contents, list):
        return ""
    return "\n".join(t for t in (extract_block_text(c) for c in contents) if t)


def audit_resource_templates(client: McpClient) -> list[ResourceFinding]:
    """Scan the metadata of every templated resource the server advertises.

    A template cannot be read without choosing a value for its parameters, so
    its body is out of reach here. Its name and description are not: those are
    the text an agent weighs when deciding whether to expand the template and
    pull the result into context, which makes them the same ingestion surface
    as a tool description and vulnerable to the same directive smuggling.

    Reported against the template expression rather than a concrete URI, since
    that is the only identifier the server gave us.
    """
    out: list[ResourceFinding] = []
    for template in client.list_resource_templates():
        text = _template_metadata(template)
        if not text:
            continue
        patterns = tuple(sorted({m.pattern for m in scan_string(text)}))
        channels = tuple(sorted({f"{c.kind} -> {c.url}" for c in scan_exfiltration_channels(text)}))
        if not patterns and not channels:
            continue
        out.append(
            ResourceFinding(
                uri=template.uri_template,
                injection_patterns=patterns,
                exfil_channels=channels,
                sample=text[:160],
            )
        )
    return out


def _template_metadata(template: ResourceTemplateDef) -> str:
    return "\n".join(part for part in (template.name, template.description) if part)


def audit_resource_content(client: McpClient) -> list[ResourceFinding]:
    """Read every listed resource and scan its content for injection and exfil."""
    out: list[ResourceFinding] = []
    for resource in client.list_resources():
        if not resource.uri:
            continue
        text = _read_resource_text(client, resource.uri)[:_MAX_SCAN_CHARS]
        if not text:
            continue
        patterns = tuple(sorted({m.pattern for m in scan_string(text)}))
        channels = tuple(sorted({f"{c.kind} -> {c.url}" for c in scan_exfiltration_channels(text)}))
        if not patterns and not channels:
            continue
        out.append(
            ResourceFinding(
                uri=resource.uri,
                injection_patterns=patterns,
                exfil_channels=channels,
                sample=text[:160],
            )
        )
    return out
