# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSRF probe targeting fetch-class MCP tools (MarkItDown, Fetch, etc.)."""

from __future__ import annotations

from dataclasses import dataclass

from ..client import McpClient
from ..content import is_tool_error, tool_result_text

_SENSITIVE_URLS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1:6379/",  # local Redis
    "file:///etc/passwd",  # file scheme
]

# What a real answer from each destination carries, keyed by the part of the
# payload that selects it. Every token here has to be something the
# destination writes and the payload does not, and the table exists so that
# invariant can be checked over the whole set rather than trusted per line.
#
# It was not, and the GCP row cost a CRITICAL false positive: the old token was
# `computemetadata`, which is a substring of the GCP payload itself, so any
# tool that echoed its argument - a log line, a refusal naming the URL it
# refused, a validator - confirmed SSRF against a target that had done nothing.
# `metadata-flavor` replaces it because the metadata server, and not the
# request, is what puts it on the wire: an unadorned fetch is refused with 403
# and a body naming the missing `Metadata-Flavor` header, which is proof the
# tool reached the metadata service even though it read nothing from it.
_INDICATORS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("169.254.169.254", ("ami-id", "instance-id")),
    ("metadata.google", ("metadata-flavor",)),
    ("/etc/passwd", ("root:",)),
    ("127.0.0.1:6379", ("redis", "noauth")),
)

_FETCH_TOOLS = ("fetch", "http", "url", "download", "convert", "markitdown")

# The answer is written by the target, and the report has to stay readable.
EVIDENCE_CHARS = 200


@dataclass(frozen=True, slots=True)
class SsrfFinding:
    tool: str
    url: str
    status: str  # OK / DENIED / ERROR
    evidence: str = ""


def probe_ssrf(client: McpClient) -> list[SsrfFinding]:
    tools = client.list_tools()
    targets = [t for t in tools if any(k in t.name.lower() for k in _FETCH_TOOLS)]
    out: list[SsrfFinding] = []
    for tool in targets:
        for url in _SENSITIVE_URLS:
            resp = client.send("tools/call", {"name": tool.name, "arguments": {"url": url}})
            if resp.is_error:
                # Explicit denial is a meaningful signal: the parameter exists
                # and is being checked. Worth recording.
                out.append(
                    SsrfFinding(
                        tool=tool.name,
                        url=url,
                        status="DENIED",
                        evidence=str(resp.error)[:200],
                    )
                )
                continue
            text = tool_result_text(resp.result)
            if is_tool_error(resp.result):
                # The spec routes tool failures into a successful response with
                # isError set, not to the JSON-RPC error field, so a server that
                # refuses the fetch lands here rather than above. Without this the
                # refusal reads as an unremarkable success and is dropped, making a
                # properly guarded tool indistinguishable from a silent one.
                out.append(SsrfFinding(tool=tool.name, url=url, status="DENIED", evidence=text[:200]))
                continue
            if _ssrf_indicator(url, text):
                # Confirmed exfiltration of sensitive content.
                out.append(SsrfFinding(tool=tool.name, url=url, status="OK", evidence=_evidence(text)))
            # Silent successes without indicators are dropped — too noisy
            # to be useful in reports.
    return out


def _evidence(text: str) -> str:
    """The answer, collapsed to one readable line.

    Carried into the report rather than dropped there. A CRITICAL row naming a
    tool and a URL asks the reader to take the match on trust; the same row
    carrying what came back lets them see for themselves whether the target
    answered or merely repeated the question - which is the whole difference
    between this finding and the false positive that produced this function.
    """
    return " ".join(text.split())[:EVIDENCE_CHARS]


def _ssrf_indicator(url: str, body: str) -> bool:
    """True when the body carries something only the destination could have written."""
    lower = body.lower()
    return any(marker in url and any(token in lower for token in tokens) for marker, tokens in _INDICATORS)
