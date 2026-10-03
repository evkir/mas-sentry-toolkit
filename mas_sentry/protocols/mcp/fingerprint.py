# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP server fingerprint - minimal info we need to attribute CVEs."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .client import McpClient
from .known_cves import KnownServer, server_for


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
    # The table entry this target matched, by the name it announced, or None. A
    # tuple is not needed: a server announces one name and the match is exact,
    # so at most one entry can apply.
    known_server: KnownServer | None = None


def fingerprint(client: McpClient, transport_name: str) -> McpFingerprint:
    # connect(), not initialize(): the stateless 2026-07-28 route has no
    # handshake, and a client that opens with one is answered -32602 on every
    # request and reports an empty server.
    info = client.connect()
    enum = client.enumerate_all()

    tools_repr = "|".join(sorted(t.name for t in enum.tools))
    tools_hash = hashlib.sha256(tools_repr.encode()).hexdigest()[:16]

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
        known_server=server_for(info.name),
    )
