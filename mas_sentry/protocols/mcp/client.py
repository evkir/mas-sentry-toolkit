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

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

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
        resp = self.transport.send(JsonRpcCodec.request("tools/list", {}, req_id=self._id()))
        if resp.is_error:
            return []
        out: list[ToolDef] = []
        for t in (resp.result or {}).get("tools", []):
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
        resp = self.transport.send(JsonRpcCodec.request("prompts/list", {}, req_id=self._id()))
        if resp.is_error:
            return []
        out: list[PromptDef] = []
        for p in (resp.result or {}).get("prompts", []):
            out.append(
                PromptDef(
                    name=p.get("name", ""),
                    description=p.get("description", ""),
                    arguments=p.get("arguments", []),
                )
            )
        return out

    def list_resources(self) -> list[ResourceDef]:
        resp = self.transport.send(JsonRpcCodec.request("resources/list", {}, req_id=self._id()))
        if resp.is_error:
            return []
        out: list[ResourceDef] = []
        for r in (resp.result or {}).get("resources", []):
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
