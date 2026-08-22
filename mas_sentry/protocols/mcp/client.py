# SPDX-License-Identifier: AGPL-3.0-or-later
"""High-level MCP client: version-aware session setup + typed enumerations.

Two protocol generations are live at once and they disagree about how a session
begins. The 2025 line opens with an `initialize` handshake, and a streamable-HTTP
server may mint an `Mcp-Session-Id` that every later request must carry. The
2026-07-28 revision removes both: there is no handshake and no session, every
request carries the protocol version, client info and capabilities in
`params._meta`, and a client that wants the capability list up front calls
`server/discover` instead.

The client tries the modern route first and falls back, rather than the reverse,
because the fallback direction is the one that stays correct as the ecosystem
moves. Two answers mean "not this generation": -32022, where the server names
the revisions it does support and we take one, and -32601, where `server/discover`
is simply unknown and the target is a 2025-line server. Anything else is a real
error and is reported as one - a scanner that treats every failure as "try the
old way" will happily downgrade itself against a server that was merely
misconfigured, and then report on a generation nobody is speaking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .jsonrpc import JsonRpcCodec, JsonRpcResponse


class Transport(Protocol):
    def send(self, req: Any) -> JsonRpcResponse: ...

    # Set by the client once the route is known. Stdio has no headers, so it
    # accepts the flag and ignores it.
    emit_routing_headers: bool
    protocol_version: str | None
    # False on STDIO, where a request has no headers to disagree with its body.
    # The header/body desync audit reads this instead of assuming a transport.
    supports_headers: bool

    def send_with_extra_headers(self, req: Any, overrides: dict[str, str]) -> JsonRpcResponse:
        """Send with caller-controlled routing headers. HTTP only; STDIO raises."""
        ...


# The revision we ask for on the stateless route, and the one we ask for when
# falling back to the handshake.
MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2025-06-18"
PROTOCOL_VERSION = LEGACY_PROTOCOL_VERSION
CLIENT_NAME = "mas-sentry"
CLIENT_VERSION = "0.2.0"
METHOD_NOT_FOUND = -32601
# The server rejected our revision and named the ones it accepts. A negotiation
# outcome, not a failure: the payload tells us what to retry with.
UNSUPPORTED_PROTOCOL_VERSION = -32022
# Headers disagreed with the body. We never provoke this by accident; a server
# that does NOT return it when provoked is itself the finding.
HEADER_MISMATCH = -32020
# The server would have elicited, sampled or listed roots, and refused because
# this client did not declare the capability. It names what it wanted in
# `data.requiredCapabilities`. The call did not run: reading this as an
# ordinary error loses the one fact that separates "the probe found nothing"
# from "the probe never reached the tool".
MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
# The 2025 line delivers URL mode as an error rather than as a result: the
# server hands over the address it wants a browser sent to and stops. The
# address is the finding, so an error read only for its code loses it.
URL_ELICITATION_REQUIRED = -32042
# The one input request that carries a consent surface. Sampling and roots ask
# the client to act; only this one asks a human to go somewhere or type
# something, which is what makes it worth auditing.
ELICITATION_METHOD = "elicitation/create"
# MCP Apps (SEP-1865, stable since 2026-01-26). A server ships an HTML document
# under a `ui://` URI, the host renders it in a sandboxed iframe, and a click
# inside that iframe fires a tool call back over the same JSON-RPC connection.
# The trust direction is the opposite of the web's: the page is supplied by the
# party being audited and rendered inside the operator's own client.
#
# The identifier and the MIME type are both load-bearing. The reference SDK
# treats the app surface as unsupported unless the client names the extension
# AND lists this MIME type in its settings (mcp 2.0.0,
# `server/apps.py:client_supports_apps`), and falls back to text-only output -
# so an undeclaring scanner sees a server with no UI at all.
APPS_EXTENSION = "io.modelcontextprotocol/ui"
APP_MIME_TYPE = "text/html;profile=mcp-app"
DISCOVER_METHOD = "server/discover"

# SEP-2322. On the 2026-07-28 route a server may answer tools/call, prompts/get
# or resources/read with a result that is not the result: `resultType` reads
# "input_required", `inputRequests` names what the server wants from the client
# (sampling, roots or an elicitation), and `requestState` is an opaque token the
# client echoes back when it retries. It arrives on the success path, so every
# reader that branches on `is_error` sees a completed call whose body happens to
# carry no content - which is indistinguishable from a tool that ran and found
# nothing. Recognising it is what keeps a suspended probe from being reported as
# a clean one.
RESULT_TYPE_KEY = "resultType"
INPUT_REQUIRED_RESULT_TYPE = "input_required"
INPUT_REQUESTS_KEY = "inputRequests"
REQUEST_STATE_KEY = "requestState"

# Envelope keys the stateless route carries in params._meta. Namespaced and
# camelCase - read off the reference SDK, not transcribed from prose.
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
# The discover result returns the server identity the same way: inside the
# result's own _meta, not at the top level where the initialize result put it.
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
# A hostile server can hand back cursors forever. Every listing is bounded, and
# hitting the bound is reported rather than silently accepted as a full result.
MAX_LIST_PAGES = 50
# The refusal payload is written by the target. Both bounds exist so that a
# server answering with a deeply nested or very wide capability object costs
# the scanner one truncated list rather than a walk it does not come back from.
MAX_CAPABILITY_DEPTH = 4
MAX_CAPABILITY_PATHS = 20
# Same reasoning for the elicitation schema: the property list is the target's
# to write, and only the first fields are worth carrying into a report.
MAX_ELICITATION_FIELDS = 40


def client_capabilities(is_modern: bool) -> dict[str, Any]:
    """Declare the elicitation modes this client can be shown, per route.

    A resolver-backed server does not describe the elicitation it would raise
    unless the client has declared the mode: the reference SDK checks the
    declaration before rendering the request and answers -32021 instead
    (mcp 2.0.0, `server/mcpserver/resolve.py`). Declaring nothing - which is
    what an empty capability object did - means a probe aimed at such a tool
    comes back as a plain error, and the consent URL or credential form the
    server would have shown is never seen.

    The routes get different declarations because the modes reach us
    differently. On 2026-07-28 an elicitation arrives inside an
    `input_required` result: the server answers and moves on, so both modes
    are observable at no cost. On the 2025 line, form mode arrives as a
    server-to-client request that the server then blocks on, and this client
    never answers an elicitation - declaring form there would trade a fast
    rejection for a read timeout and a server left waiting. URL mode on that
    line arrives as error -32042, which costs nothing.

    Two shapes are not interchangeable: a bare `elicitation: {}` reads as form
    support to the reference SDK, and a url-only object does not read as form.
    The modes are named explicitly for that reason. Sampling and roots stay
    undeclared - both would have the server ask this client to act.

    The MCP Apps extension is declared on the modern route for the same reason
    the elicitation modes are: a server that sees no declaration serves text
    instead of its UI, and the surface goes unaudited rather than unfound.
    Declaring it costs nothing here - this client parses what the server
    advertises and never renders an iframe or executes what is inside one. The
    2025 line has no `extensions` field at all, so nothing is claimed there.
    """
    modes: dict[str, Any] = {"form": {}, "url": {}} if is_modern else {"url": {}}
    out: dict[str, Any] = {"elicitation": modes}
    if is_modern:
        out["extensions"] = {APPS_EXTENSION: {"mimeTypes": [APP_MIME_TYPE]}}
    return out


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
    """One entry from `resources/list`, kept whole.

    The listing was read for three scalars and the rest discarded, which was
    fine while a resource was only ever a body to fetch. MCP Apps changed that:
    a `ui://` resource declares, in its `_meta.ui`, the Content-Security-Policy
    domains its iframe may reach and the browser permissions it asks the host
    to grant. Those declarations are the audit surface - the HTML is what it
    does, `_meta.ui` is what it is allowed to do - and a parser that keeps the
    URI and drops the rest reports on a UI without knowing whether it may call
    home.
    """

    uri: str
    name: str = ""
    mime_type: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


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


@dataclass(frozen=True, slots=True)
class InputRequired:
    """One call the server suspended pending input from the client.

    Recorded, never answered. Fulfilling an input request would mean the scanner
    sampling a model, exposing filesystem roots, or answering an elicitation on
    an operator's behalf, and each of those is an action rather than an
    observation. What the report needs is the fact itself: a probe that stopped
    here established nothing about the method it was aimed at, and a scan that
    omits that reads as coverage it never had.
    """

    method: str
    kinds: tuple[str, ...]
    has_request_state: bool

    @property
    def severity(self) -> str:
        """Not a vulnerability - a hole in what this scan can claim to have tested."""
        return "MEDIUM"

    @property
    def detail(self) -> str:
        kinds = ", ".join(self.kinds) if self.kinds else "no input request named"
        state = "with" if self.has_request_state else "without"
        return (
            f"{self.method} was suspended pending client input ({kinds}), "
            f"{state} a requestState to echo. Probes against this method reached no result."
        )


@dataclass(frozen=True, slots=True)
class ElicitationRequest:
    """One elicitation the server sent, kept as it arrived.

    Recording that a call was suspended says a probe stopped; it does not say
    what the server asked a human to do. That question is answered entirely by
    the request parameters - the address a browser would be sent to in URL
    mode, the properties a form would collect in form mode - and those are the
    only part of the exchange an operator can act on. Reading the request for
    its method alone and dropping its params keeps the fact of the suspension
    and throws away its content.

    Both routes land here. On 2026-07-28 the request arrives inside an
    `input_required` result; on the 2025 line URL mode arrives as error -32042
    instead. `elicitationId` is deliberately not read: it was removed from URL
    mode in 2026-07-28, and a parser that needs it would stop working against
    a current server for the sake of a value that identifies nothing to us.
    """

    method: str
    mode: str
    message: str
    url: str
    fields: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class CapabilityGap:
    """One call the server refused because the client declared too little.

    The refusal arrives on the error path with a `requiredCapabilities`
    payload naming what the server wanted, and it is emphatically not a
    failure of the target: the server behaved correctly and said so. What it
    means for the scan is that the tool behind that method was never reached,
    so every probe aimed at it established nothing. Reported for the same
    reason a suspended call is - the alternative is a report where an
    unexercised surface is indistinguishable from a clean one.
    """

    method: str
    capabilities: tuple[str, ...]
    message: str

    @property
    def severity(self) -> str:
        """Not a weakness in the target - a hole in what this scan can claim."""
        return "MEDIUM"

    @property
    def detail(self) -> str:
        wanted = ", ".join(self.capabilities) if self.capabilities else "no capability named"
        return (
            f"{self.method} was refused for a client capability this scanner does not "
            f"offer ({wanted}): {self.message}. Probes against this method reached no result."
        )


@dataclass(frozen=True, slots=True)
class ResourceTemplateDef:
    """A parameterised resource URI the server will expand on request.

    Templates are listed by their own method and never appear in
    `resources/list`, so a client that asks only for concrete resources sees a
    server with fewer of them than it has - and the description field, which is
    what the model reads when deciding to fetch, goes unscanned.
    """

    uri_template: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


@dataclass(slots=True)
class Enumeration:
    """Aggregated result of one full server enumeration pass."""

    tools: list[ToolDef] = field(default_factory=list)
    prompts: list[PromptDef] = field(default_factory=list)
    resources: list[ResourceDef] = field(default_factory=list)
    resource_templates: list[ResourceTemplateDef] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.tools) + len(self.prompts) + len(self.resources) + len(self.resource_templates)


class McpClient:
    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self._next_id = 0
        self.server: ServerInfo | None = None
        self.enumeration_issues: list[EnumerationIssue] = []
        # Route state. Set by connect(); until then we assume nothing.
        self.is_modern = False
        self.protocol_version = LEGACY_PROTOCOL_VERSION
        self.discover_result: dict[str, Any] = {}
        # Calls the server suspended instead of answering. See InputRequired.
        self.input_required: list[InputRequired] = []
        # Calls the server refused for want of a capability. See CapabilityGap.
        self.capability_gaps: list[CapabilityGap] = []
        # Elicitations the server sent on either route. See ElicitationRequest.
        self.elicitations: list[ElicitationRequest] = []

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
            resp = self.send(method, params)
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

    def envelope(self, params: dict[str, Any] | None) -> dict[str, Any]:
        """Add the stateless protocol envelope to a request's params.

        On the modern route every request restates the version, the client
        identity and the client capabilities; there is no handshake that could
        have established them once. The keys are namespaced and camelCase.
        """
        out = dict(params or {})
        meta = dict(out.get("_meta") or {})
        meta.setdefault(META_PROTOCOL_VERSION, self.protocol_version)
        meta.setdefault(META_CLIENT_INFO, {"name": CLIENT_NAME, "version": CLIENT_VERSION})
        meta.setdefault(META_CLIENT_CAPABILITIES, client_capabilities(True))
        out["_meta"] = meta
        return out

    @staticmethod
    def input_required_of(resp: JsonRpcResponse) -> dict[str, Any] | None:
        """Return the suspended-call payload, or None when this is a real result.

        Callers that need to know whether they were answered ask here rather
        than inspecting `result` for emptiness: an empty body is a legitimate
        answer from plenty of tools, and conflating the two is the defect.
        """
        result = resp.result
        if not isinstance(result, dict):
            return None
        if result.get(RESULT_TYPE_KEY) != INPUT_REQUIRED_RESULT_TYPE:
            return None
        return result

    def _note_input_required(self, method: str, resp: JsonRpcResponse) -> None:
        """Record a suspended call once per distinct (method, requested inputs)."""
        result = self.input_required_of(resp)
        if result is None:
            return
        requests = result.get(INPUT_REQUESTS_KEY)
        kinds: list[str] = []
        if isinstance(requests, dict):
            for entry in requests.values():
                if not isinstance(entry, dict):
                    continue
                name = entry.get("method")
                if not isinstance(name, str) or not name:
                    continue
                if name not in kinds:
                    kinds.append(name)
                if name == ELICITATION_METHOD:
                    self._keep_elicitation(self._elicitation_of(method, entry.get("params")))
        record = InputRequired(
            method=method,
            kinds=tuple(sorted(kinds)),
            has_request_state=isinstance(result.get(REQUEST_STATE_KEY), str),
        )
        if record not in self.input_required:
            self.input_required.append(record)

    @staticmethod
    def _capability_paths(payload: Any, prefix: str = "") -> list[str]:
        """Flatten a capability object into dotted leaf paths, bounded.

        `{"elicitation": {"form": {}}}` reads as `elicitation.form`, which is
        the shape an operator can act on. The walk is bounded in depth and in
        breadth because the payload comes from the target: an unbounded walk
        over a hostile structure is a denial of service against the scanner.
        """
        if not isinstance(payload, dict) or not payload or prefix.count(".") >= MAX_CAPABILITY_DEPTH:
            return [prefix] if prefix else []
        out: list[str] = []
        for key in sorted(str(k) for k in payload):
            out.extend(McpClient._capability_paths(payload[key], f"{prefix}.{key}" if prefix else key))
            if len(out) >= MAX_CAPABILITY_PATHS:
                return out[:MAX_CAPABILITY_PATHS]
        return out

    def _note_capability_gap(self, method: str, resp: JsonRpcResponse) -> None:
        """Record a call refused for a missing capability, once per distinct refusal."""
        if not resp.is_error:
            return
        error = resp.error or {}
        if error.get("code") != MISSING_REQUIRED_CLIENT_CAPABILITY:
            return
        data = error.get("data")
        required = data.get("requiredCapabilities") if isinstance(data, dict) else None
        record = CapabilityGap(
            method=method,
            capabilities=tuple(self._capability_paths(required)),
            message=str(error.get("message", "no message"))[:200],
        )
        if record not in self.capability_gaps:
            self.capability_gaps.append(record)

    @staticmethod
    def _elicitation_of(method: str, params: Any) -> ElicitationRequest | None:
        """Parse one elicitation request's params, or None when unreadable.

        The mode is taken from the wire when the server names it and inferred
        from the shape when it does not: a 2025-line server predating modes
        sends a schema and no `mode` at all, and treating that as unparseable
        would drop the exact case where the client is oldest and the operator
        least likely to be looking.
        """
        if not isinstance(params, dict):
            return None
        schema = params.get("requestedSchema")
        url = params.get("url")
        mode = params.get("mode")
        if not isinstance(mode, str) or not mode:
            mode = "form" if isinstance(schema, dict) else ("url" if isinstance(url, str) else "")
        fields: list[tuple[str, str]] = []
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if isinstance(properties, dict):
            for key in sorted(properties, key=str)[:MAX_ELICITATION_FIELDS]:
                spec = properties[key]
                description = ""
                if isinstance(spec, dict):
                    description = str(spec.get("description") or spec.get("title") or "")[:200]
                fields.append((str(key), description))
        return ElicitationRequest(
            method=method,
            mode=mode,
            message=str(params.get("message", ""))[:300],
            url=url if isinstance(url, str) else "",
            fields=tuple(fields),
        )

    def _keep_elicitation(self, request: ElicitationRequest | None) -> None:
        if request is not None and request not in self.elicitations:
            self.elicitations.append(request)

    def _note_url_elicitation(self, method: str, resp: JsonRpcResponse) -> None:
        """Record the addresses a -32042 refusal wants a browser sent to."""
        if not resp.is_error:
            return
        error = resp.error or {}
        if error.get("code") != URL_ELICITATION_REQUIRED:
            return
        data = error.get("data")
        entries = data.get("elicitations") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return
        for entry in entries[:MAX_ELICITATION_FIELDS]:
            self._keep_elicitation(self._elicitation_of(method, entry))

    def send(self, method: str, params: dict[str, Any] | None = None) -> JsonRpcResponse:
        """Send one request on whichever route this client negotiated."""
        if self.is_modern:
            params = self.envelope(params)
        resp = self.transport.send(JsonRpcCodec.request(method, params, req_id=self._id()))
        self._note_input_required(method, resp)
        self._note_capability_gap(method, resp)
        self._note_url_elicitation(method, resp)
        return resp

    def connect(self) -> ServerInfo:
        """Establish a session, trying the stateless route before the handshake.

        Returns the same ServerInfo either way, so callers do not branch on the
        generation. `discover_result` keeps the raw modern payload for the
        caching metadata the handshake has no equivalent for.
        """
        info = self._try_discover()
        if info is not None:
            return info
        return self.initialize()

    def _try_discover(self) -> ServerInfo | None:
        """Attempt the stateless route. None means "this server is not modern"."""
        self.is_modern = True
        self.protocol_version = MODERN_PROTOCOL_VERSION
        self.transport.emit_routing_headers = True
        self.transport.protocol_version = self.protocol_version

        resp = self.send(DISCOVER_METHOD)
        if not resp.is_error:
            return self._adopt_discover(resp)

        error = resp.error or {}
        code = error.get("code")
        if code == UNSUPPORTED_PROTOCOL_VERSION:
            # The server named what it accepts. Retry once on the newest
            # revision it offers; if it offers the very version it just
            # rejected, retrying would loop, so treat it as a legacy target.
            offered = self._offered_versions(error)
            if offered and MODERN_PROTOCOL_VERSION not in offered:
                self.protocol_version = max(offered)
                self.transport.protocol_version = self.protocol_version
                retry = self.send(DISCOVER_METHOD)
                if not retry.is_error:
                    return self._adopt_discover(retry)
        # -32601 means the method is unknown, so this is a 2025-line server.
        # Anything else is a real fault: falling back still gives the handshake
        # a chance to speak, but we do not pretend we learned a protocol fact.
        return None

    @staticmethod
    def _offered_versions(error: dict[str, Any]) -> list[str]:
        data = error.get("data")
        if not isinstance(data, dict):
            return []
        supported = data.get("supported")
        if not isinstance(supported, list):
            return []
        return [v for v in supported if isinstance(v, str) and v]

    def _adopt_discover(self, resp: JsonRpcResponse) -> ServerInfo:
        result = resp.result if isinstance(resp.result, dict) else {}
        self.discover_result = result
        # Verified against the reference SDK: discover returns the server
        # identity nested in result._meta under a namespaced key, where the
        # handshake returned a top-level serverInfo. Reading the old place
        # yields a server with no name and no version, and a fingerprint that
        # matches no known implementation.
        meta = result.get("_meta")
        nested = meta.get(META_SERVER_INFO) if isinstance(meta, dict) else None
        top_level = result.get("serverInfo")
        info: dict[str, Any] = {}
        if isinstance(nested, dict):
            info = nested
        elif isinstance(top_level, dict):
            info = top_level
        self.server = ServerInfo(
            name=str(info.get("name", "")),
            version=str(info.get("version", "")),
            protocol_version=str(result.get("protocolVersion") or self.protocol_version),
            capabilities=result.get("capabilities") or {},
            instructions=str(result.get("instructions", "")),
        )
        return self.server

    def initialize(self) -> ServerInfo:
        self.is_modern = False
        self.protocol_version = LEGACY_PROTOCOL_VERSION
        self.transport.emit_routing_headers = False
        req = JsonRpcCodec.request(
            "initialize",
            {
                "protocolVersion": LEGACY_PROTOCOL_VERSION,
                "capabilities": client_capabilities(False),
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
                    meta=raw_meta if isinstance(raw_meta := r.get("_meta"), dict) else {},
                )
            )
        return out

    def list_resource_templates(self) -> list[ResourceTemplateDef]:
        out: list[ResourceTemplateDef] = []
        for t in self._list_paged("resources/templates/list", "resourceTemplates"):
            out.append(
                ResourceTemplateDef(
                    uri_template=t.get("uriTemplate", ""),
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    mime_type=t.get("mimeType", ""),
                )
            )
        return out

    def enumerate_all(self) -> Enumeration:
        """Single pass over every inventory the server exposes.

        Failures are recorded as enumeration issues rather than swallowed, so a
        listing that did not come back is distinguishable from one that came
        back empty.
        """
        return Enumeration(
            tools=self.list_tools(),
            prompts=self.list_prompts(),
            resources=self.list_resources(),
            resource_templates=self.list_resource_templates(),
        )
