# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP server fingerprint — minimal info we need to attribute CVEs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .client import McpClient


@dataclass(frozen=True, slots=True)
class McpFingerprint:
    name: str
    version: str
    protocol_version: str
    transport: str
    capabilities: dict[str, Any] = field(default_factory=dict)
    tool_count: int = 0
    prompt_count: int = 0
    resource_count: int = 0
    tools_hash: str = ""
    suspected_impls: list[str] = field(default_factory=list)


_KNOWN_VULN_IMPLS = {
    "mcp-server-git": ["CVE-2025-68143", "CVE-2025-68144", "CVE-2025-68145"],
    "markitdown": ["MarkItDown-MCP-SSRF-2026"],
    "gemini-mcp-tool": ["CVE-2026-0755"],
    "github-kanban": ["CVE-2026-0756"],
    "orval-mcp": ["CVE-2026-22785", "CVE-2026-23947"],
}


def fingerprint(client: McpClient, transport_name: str) -> McpFingerprint:
    # connect(), not initialize(): the stateless 2026-07-28 route has no
    # handshake, and a client that opens with one is answered -32602 on every
    # request and reports an empty server.
    info = client.connect()
    enum = client.enumerate_all()

    tools_repr = "|".join(sorted(t.name for t in enum.tools))
    tools_hash = hashlib.sha256(tools_repr.encode()).hexdigest()[:16]

    name_lc = info.name.lower()
    suspected = [impl for impl in _KNOWN_VULN_IMPLS if impl in name_lc]
    return McpFingerprint(
        name=info.name,
        version=info.version,
        protocol_version=info.protocol_version,
        transport=transport_name,
        capabilities=info.capabilities,
        tool_count=len(enum.tools),
        prompt_count=len(enum.prompts),
        resource_count=len(enum.resources),
        tools_hash=tools_hash,
        suspected_impls=suspected,
    )


def known_cves_for(name: str) -> list[str]:
    """Case-insensitive lookup. Accepts a raw server name or a normalised key."""
    return _KNOWN_VULN_IMPLS.get(name.lower(), [])
