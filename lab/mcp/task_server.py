# SPDX-License-Identifier: AGPL-3.0-or-later
"""An MCP server that defers tool calls to tasks, on the reference SDK's own extension API.

The Tasks extension (SEP-2663) is not shipped by the SDK, so the deferral
itself is written here - but everything around it is the SDK's: the extension
is registered through `MCPServer(extensions=[...])`, so `server/discover`
advertises it the way the SDK advertises any extension; the deferral is
returned from `intercept_tool_call`, so it is serialized and stamped by the
same path a real handler result takes; and the capability check is the SDK's
`require_client_extension`, not a reimplementation of it.

That last point is why this rig exists rather than a fixture. The extension
states a server MUST NOT return a task to a client that did not carry the
extension capability on its request, and the interesting question for MST is
what that looks like on the wire when the SDK decides the shape. Three modes,
because a server has three honest answers to a client that never asked for
tasks and MST has to tell them apart.

Environment:
    MAS_SENTRY_TASK_TRANSPORT  "stdio" (default) or "streamable-http"
    MAS_SENTRY_TASK_HOST       bind address for http (default 127.0.0.1)
    MAS_SENTRY_TASK_PORT       port for http (default 9820)
    MAS_SENTRY_TASK_BREAK      "" runs the tool for a client that did not
                               declare the extension, which is conformant and
                               must leave no task row at all; "refuse" answers
                               such a client with -32021, also conformant and
                               already reported as a capability gap;
                               "undeclared" defers anyway, which is the
                               violation the audit is for.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.extension import Extension, MethodBinding
from mcp.server.mcpserver import MCPServer, require_client_extension
from mcp.shared.exceptions import MCPError
from mcp_types import CallToolRequestParams, RequestParams

TASKS_EXTENSION = "io.modelcontextprotocol/tasks"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9820
TASK_ID = "task-lab-1"
TASK_TTL_MS = 600000
TASK_POLL_INTERVAL_MS = 500

BREAK = os.environ.get("MAS_SENTRY_TASK_BREAK", "")


class TasksGetParams(RequestParams):
    """Params for `tasks/get`. Subclasses RequestParams so `_meta` parses uniformly."""

    taskId: str


class TasksExtension(Extension):
    """Defers every tool call to a task handle and serves the poll method.

    The handle is deliberately durable and slow: `working` forever, with a TTL
    of ten minutes. A client that polls it spends that TTL and learns nothing,
    which is the cost a scanner takes on the moment it accepts the extension -
    and the reason MST records the handle instead of following it.
    """

    identifier = TASKS_EXTENSION

    def methods(self) -> Sequence[MethodBinding]:
        return (MethodBinding(method="tasks/get", params_type=TasksGetParams, handler=self._get),)

    async def _get(self, ctx: ServerRequestContext[Any, Any], params: TasksGetParams) -> HandlerResult:
        return {"taskId": params.taskId, "status": "working", "ttlMs": TASK_TTL_MS}

    async def intercept_tool_call(
        self,
        params: CallToolRequestParams,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        if BREAK != "undeclared":
            # The SDK decides whether the client asked for this, and raises
            # -32021 when it did not. Writing that check by hand is how a rig
            # ends up agreeing with the scanner instead of testing it. What
            # the two conformant modes differ on is what to do with the
            # refusal: let it reach the client, or run the tool instead.
            try:
                require_client_extension(ctx, TASKS_EXTENSION)
            except MCPError:
                if BREAK == "refuse":
                    raise
                return await call_next(ctx)
        return {
            "resultType": "task",
            "task": {
                "taskId": TASK_ID,
                "status": "working",
                "ttlMs": TASK_TTL_MS,
                "pollIntervalMs": TASK_POLL_INTERVAL_MS,
            },
        }


srv = MCPServer(
    name="task-mcp-ref",
    version="0.1.0",
    instructions="Reference-SDK lab server for MAS-Sentry. Defers tool calls to tasks.",
    extensions=[TasksExtension()],
)


@srv.tool()
def echo(text: str) -> str:
    """Return the text unchanged. Never actually reached while deferral is on."""
    return text


@srv.tool()
def read_file(path: str) -> str:
    """Would read any path. Present so the traversal probe has something to aim at.

    Answers without repeating the argument. A tool that echoes its input hands
    the probe back the very tokens the probe is looking for, and the rig
    manufactures the finding it was built to be a clean baseline for.
    """
    return "0 bytes read"


@srv.tool()
def fetch_url(url: str) -> str:
    """Would dereference any URL. Present so the SSRF probe has something to aim at."""
    return "0 bytes fetched"


def main() -> None:
    """Run the rig on the transport named by MAS_SENTRY_TASK_TRANSPORT."""
    if os.environ.get("MAS_SENTRY_TASK_TRANSPORT", "stdio") == "stdio":
        srv.run(transport="stdio")
        return
    srv.run(
        transport="streamable-http",
        host=os.environ.get("MAS_SENTRY_TASK_HOST", DEFAULT_HOST),
        port=int(os.environ.get("MAS_SENTRY_TASK_PORT", DEFAULT_PORT)),
    )


if __name__ == "__main__":
    main()
