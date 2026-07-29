# SPDX-License-Identifier: AGPL-3.0-or-later
"""High-level MCP client: initialize handshake + typed enumerations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .jsonrpc import JsonRpcCodec, JsonRpcResponse


class Transport(Protocol):
    def send(self, req: Any) -> JsonRpcResponse: ...


PROTOCOL_VERSION = "2025-06-18"  # spec rev — bump as needed
CLIENT_NAME = "mas-sentry"
CLIENT_VERSION = "0.2.0"
METHOD_NOT_FOUND = -32601
# A hostile server can hand back cursors forever. Every listing is bounded, and
# hitting the bound is reported rather than silently accepted as a full result.
MAX_LIST_PAGES = 50


@dataclass(slots=True)
class ServerInfo:
    name: str = ""
    version: str = ""
    protocol_version: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)
    instructions: str = ""


@dataclass(slots=True)
class ToolDef:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PromptDef:
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ResourceDef:
    uri: str
    name: str = ""
    mime_type: str = ""


@dataclass(frozen=True, slots=True)
class EnumerationIssue:
    """One inventory listing that did not come back.

    An empty list and a refused listing are the same value to every caller
    downstream, and the difference is the whole finding: a server with tools
    that would not list them is unaudited, while a server with no tools is
    clean. Recording the method and the JSON-RPC code keeps the two apart all
    the way into the report.
    """

    method: str
    code: int | None
    message: str

    @property
    def severity(self) -> str:
        """A method the server never implemented is expected; anything else is not.

        `-32601` means the surface does not exist, which is worth stating once
        and no more. Every other outcome - an authorization refusal, a transport
        error, an HTTP status folded into the error field - means the surface
        may well exist and went unexamined.
        """
        return "INFO" if self.code == METHOD_NOT_FOUND else "MEDIUM"

    @property
    def detail(self) -> str:
        code = "no code" if self.code is None else f"code {self.code}"
        return f"{self.method} did not return a complete inventory: {self.message} ({code})"


@dataclass(slots=True)
class Enumeration:
    """Aggregated result of one full server enumeration pass."""

    tools: list[ToolDef] = field(default_factory=list)
    prompts: list[PromptDef] = field(default_factory=list)
    resources: list[ResourceDef] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.tools) + len(self.prompts) + len(self.resources)


class McpClient:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self._next_id = 0
        self.server: ServerInfo | None = None
        self.enumeration_issues: list[EnumerationIssue] = []

    def _record_issue(self, method: str, error: dict[str, Any] | None) -> None:
        """Remember a listing that failed, once per method."""
        if any(issue.method == method for issue in self.enumeration_issues):
            return
        error = error or {}
        code = error.get("code")
        self.enumeration_issues.append(
            EnumerationIssue(
                method=method,
                code=code if isinstance(code, int) else None,
                message=str(error.get("message", "no message"))[:200],
            )
        )

    def _list_paged(self, method: str, key: str) -> list[dict[str, Any]]:
        """Walk every page of a list method and return the raw entries.

        MCP list results are paginated: a server answers with a slice and a
        `nextCursor`, and the client is expected to keep asking until the cursor
        is absent. Reading only the first page is the quiet version of the
        empty-inventory defect - a server with more tools than fit one page gets
        audited on the prefix, and the tools an attacker would care about are as
        likely to sit past the cut as before it.

        Two failure modes are treated as findings rather than as results. A
        server that repeats a cursor, or that never stops issuing them, would
        otherwise spin the scanner indefinitely; the walk is bounded, and both
        outcomes are recorded so a truncated inventory is never presented as a
        complete one.
        """
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_LIST_PAGES):
            params: dict[str, Any] = {} if cursor is None else {"cursor": cursor}
            resp = self.transport.send(JsonRpcCodec.request(method, params, req_id=self._id()))
            if resp.is_error:
                self._record_issue(method, resp.error)
                return items
            result = resp.result if isinstance(resp.result, dict) else {}
            page = result.get(key)
            if isinstance(page, list):
                items.extend(entry for entry in page if isinstance(entry, dict))
            nxt = result.get("nextCursor")
            if not isinstance(nxt, str) or not nxt:
                return items
            if nxt in seen:
                self._record_issue(method, {"message": f"server repeated pagination cursor {nxt!r}"})
                return items
            seen.add(nxt)
            cursor = nxt
        self._record_issue(method, {"message": f"pagination did not terminate within {MAX_LIST_PAGES} pages"})
        return items

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def next_id(self) -> int:
        """Public counter shared with auditors/probes that need request IDs."""
        return self._id()

    def initialize(self) -> ServerInfo:
        req = JsonRpcCodec.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
            req_id=self._id(),
        )
        resp = self.transport.send(req)
        if resp.is_error:
            raise RuntimeError(f"initialize failed: {resp.error}")
        result = resp.result or {}
        info = result.get("serverInfo", {})
        self.server = ServerInfo(
            name=info.get("name", ""),
            version=info.get("version", ""),
            protocol_version=result.get("protocolVersion", ""),
            capabilities=result.get("capabilities", {}),
            instructions=result.get("instructions", ""),
        )
        # send notifications/initialized
        self.transport.send(JsonRpcCodec.notification("notifications/initialized"))
        return self.server

    def list_tools(self) -> list[ToolDef]:
        out: list[ToolDef] = []
        for t in self._list_paged("tools/list", "tools"):
            out.append(
                ToolDef(
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                    raw=t,
                )
            )
        return out

    def list_prompts(self) -> list[PromptDef]:
        out: list[PromptDef] = []
        for p in self._list_paged("prompts/list", "prompts"):
            out.append(
                PromptDef(
                    name=p.get("name", ""),
                    description=p.get("description", ""),
                    arguments=p.get("arguments", []),
                )
            )
        return out

    def list_resources(self) -> list[ResourceDef]:
        out: list[ResourceDef] = []
        for r in self._list_paged("resources/list", "resources"):
            out.append(
                ResourceDef(
                    uri=r.get("uri", ""),
                    name=r.get("name", ""),
                    mime_type=r.get("mimeType", ""),
                )
            )
        return out

    def enumerate_all(self) -> Enumeration:
        """Single pass: tools + prompts + resources. Errors degrade to empty lists."""
        return Enumeration(
            tools=self.list_tools(),
            prompts=self.list_prompts(),
            resources=self.list_resources(),
        )
