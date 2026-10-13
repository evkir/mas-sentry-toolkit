# SPDX-License-Identifier: AGPL-3.0-or-later
"""A tool filter applied to discovery and not to execution. DO NOT DEPLOY.

Source: CVE-2026-46519 (`mcp-server-kubernetes` 0.2.4-3.5.1, fixed in 3.6.0,
CWE-863, CVSS 8.8; OSV / GHSA-cr22-wjx7-2w6m). `ALLOW_ONLY_READONLY_TOOLS`,
`ALLOW_ONLY_NON_DESTRUCTIVE_TOOLS` and `ALLOWED_TOOLS` were honoured by the
`tools/list` handler and by nothing else, so any client holding a tool's name
reached it through `tools/call`. Read off the published packages rather than
off a write-up: 3.5.1 and 3.6.0 ship identical file trees, and the whole fix is
one guard added to the `CallToolRequestSchema` handler that the listing handler
already had.

Three modes, chosen by `MAS_SENTRY_DESYNC_MODE`, because a detector is only
worth shipping if the fixed shape makes it stay quiet (R-2.4):

    off        no filter at all. This is the state an operator approved the
               inventory in, and the run that captures a baseline holding the
               tool's name and schema.
    list-only  the defect. `sweep_cluster` is filtered out of the listing and
               remains callable.
    both       the fix. The same allowlist decides the listing and the call.

One caveat about the fixed mode, measured rather than assumed: the Python SDK
turns a refusal raised in middleware into `-32603 Internal server error`, while
the TypeScript SDK that the real 3.6.0 fix is written in answers `-32600`. The
codes differ, the class of answer does not - both are a JSON-RPC error rather
than a tool result - and nothing downstream is allowed to read the code, for
exactly this reason.

The filter is installed through the SDK's own middleware chain rather than by
reaching into handler internals, so what the wire carries is the SDK's doing
and not this file's. That matters for what MST reads off it: the response to a
call naming a filtered-out tool is produced by the same code path that answers
any other call.

Environment:
    MAS_SENTRY_DESYNC_MODE    "list-only" (default), "off" or "both"
    MAS_SENTRY_DESYNC_MARKER  a path the hidden tool's body writes if it ever
                              runs. Nothing in a correct scan should create it:
                              the probe's whole claim is that it establishes
                              reachability without executing the tool (R-7.6),
                              and this marker is what holds it to that.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_REQUEST, ErrorData

FILTERED = frozenset({"sweep_cluster"})

app = MCPServer("desync-rig")


@app.tool()
def visible_echo(text: str) -> str:
    """Announced throughout. One required string, so an invalid call is cheap to build."""
    return text


@app.tool()
def sweep_cluster(namespace: str) -> str:
    """Filtered out of the listing. Whether it is callable is the question under test."""
    marker = os.environ.get("MAS_SENTRY_DESYNC_MARKER")
    if marker:
        Path(marker).write_text("BODY_EXECUTED", encoding="utf-8")
    return f"swept {namespace}"


def _mode() -> str:
    return os.environ.get("MAS_SENTRY_DESYNC_MODE", "list-only")


def _without_filtered(result: dict[str, Any]) -> dict[str, Any]:
    kept = []
    for tool in result.get("tools", []):
        name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
        if name not in FILTERED:
            kept.append(tool)
    result["tools"] = kept
    return result


async def _enforce(ctx: Any, call_next: Any) -> Any:
    """The allowlist, applied at whichever levels this mode claims to apply it."""
    mode = _mode()
    if mode == "both" and ctx.method == "tools/call":
        params = ctx.params if isinstance(ctx.params, dict) else {}
        name = params.get("name")
        if name in FILTERED:
            raise MCPError(
                ErrorData(
                    code=INVALID_REQUEST,
                    message=f"Tool '{name}' is not allowed under the current server configuration",
                )
            )
    result = await call_next(ctx)
    if mode != "off" and ctx.method == "tools/list" and isinstance(result, dict):
        return _without_filtered(result)
    return result


app.middleware.append(_enforce)


if __name__ == "__main__":
    app.run()
