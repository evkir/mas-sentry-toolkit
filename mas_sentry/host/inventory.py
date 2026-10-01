# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read a located agent-host config into one normalised server inventory.

Four dialects describe the same thing differently. VS Code keys the server map
on `servers`, everyone else on `mcpServers`. Cursor requires `type` on a local
server and marks a remote one by the presence of `url`; VS Code states the
transport outright; Claude Desktop states neither. Secrets reach a server
through `env`, `envFile`, `headers` or an OAuth block depending on the host.

What this module does NOT do is decide anything. It records what the file says
in one shape, and the detectors judge. An inventory that inferred "this is an
HTTP server" from a missing field would hide the fact that the file never said
so, and the gap between what a config declares and what a host does with it is
exactly where this operation's findings live.

Two properties are load-bearing:

Values are never retained. A config holds API keys, so an entry records the
*shape* of each value - literal, a substitution reference, a mix of both - with
the reference names but never the literal text. A detector can then report "a
32-character literal sits in env ANTHROPIC_API_KEY" without the key reaching a
report, and the guarantee is in the type rather than in a filter somebody has
to remember to apply. `${input:api-key}` is the safe pattern a host offers and
reads here as a reference, which is what keeps the secret detector from firing
on a config that does the right thing.

Nothing is dropped silently. A key this module does not model is listed in
`unmodelled` rather than ignored, and a file that exists but cannot be parsed
produces a stated reason rather than an empty server list (R-2.1).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from .discovery import HostConfig

SERVER_MAP_KEYS: Final = ("mcpServers", "servers")
"""Top-level keys that hold the server map, in the order they are tried."""

# Fields an entry is read into. A key outside this set lands in `unmodelled`,
# which is how a host adding a field becomes visible instead of invisible.
_MODELLED_SERVER_KEYS: Final = frozenset({"type", "command", "args", "env", "envFile", "cwd", "url", "headers"})

# `${...}` placeholder. The body is bounded: a config is operator-supplied text,
# and an unclosed brace in a minified one-line file would otherwise let one
# placeholder run to the end of the document.
_PLACEHOLDER: Final = re.compile(r"\$\{([^}]{0,200})\}")


@dataclass(frozen=True, slots=True)
class ValueShape:
    """What a config value is, never what it says.

    `form` is one of: `empty`, `reference` (the whole value is one placeholder),
    `mixed` (placeholders plus other text), `literal` (no placeholder at all).
    `length` is the raw value's length, which lets a report distinguish a short
    flag from something key-shaped without carrying either.
    """

    form: str
    references: tuple[str, ...]
    length: int


@dataclass(frozen=True, slots=True)
class EnvEntry:
    key: str
    shape: ValueShape


@dataclass(frozen=True, slots=True)
class ServerEntry:
    """One server as its config declares it.

    `declared_type` is `None` when the file omits it - not a guess at what the
    host would negotiate. `command` and `url` are likewise recorded as found,
    so "declares both" and "declares neither" stay visible as the malformed
    shapes they are.
    """

    name: str
    declared_type: str | None
    command: str | None
    args: tuple[str, ...]
    env: tuple[EnvEntry, ...]
    env_file: str | None
    cwd: str | None
    url: str | None
    header_names: tuple[str, ...]
    unmodelled: frozenset[str]


@dataclass(frozen=True, slots=True)
class InputDecl:
    """A VS Code `inputs` entry: a value the host prompts for instead of storing.

    `is_password` marks the declaration that keeps a secret out of the file
    altogether. A `command` input is different in kind - it runs something to
    produce the value - so the command is recorded.
    """

    input_id: str
    kind: str
    is_password: bool
    command: str | None


@dataclass(frozen=True, slots=True)
class Inventory:
    """The normalised reading of one config file.

    `unreadable` carries why there is nothing to report when that is the case:
    the file is absent, or it is present and could not be parsed. It is `None`
    for a file that parsed, including one that genuinely declares no servers -
    which is the distinction a report must preserve.
    """

    source: HostConfig
    dialect: str | None
    servers: tuple[ServerEntry, ...]
    inputs: tuple[InputDecl, ...]
    unmodelled_top_level: frozenset[str]
    unreadable: str | None


def _strip_comments(text: str) -> str:
    """Remove `//` and `/* */` comments, leaving string contents alone.

    VS Code reads `.vscode/mcp.json` as JSONC, so a comment is valid input that
    `json.loads` rejects. Calling such a file malformed would be a finding about
    this parser rather than about the operator's config (R-2.4).

    The scan tracks string state because `//` inside a value - every `https://`
    URL in the file - is data, not a comment.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _drop_trailing_commas(text: str) -> str:
    """Remove a comma that is followed only by a closing brace or bracket.

    A separate pass rather than part of the comment scan, because a trailing
    comma may be separated from its brace by a comment: `{"a": 1, // note\\n}`.
    Running after comments are gone makes the lookahead reliable without a
    parser that has to understand both at once.

    String state is tracked here too: `{"a": "x, }"}` is a valid document whose
    value contains that exact sequence, and a blind substitution would rewrite
    the operator's data.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def shape_of(value: object) -> ValueShape:
    """Classify a config value without keeping it.

    A non-string value (a number, a bool, a nested object) is reported as a
    literal of its rendered length: it carries no placeholder, and its content
    is no more ours to keep than a string's.
    """
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    if not text:
        return ValueShape(form="empty", references=(), length=0)
    found = tuple(m.group(1) for m in _PLACEHOLDER.finditer(text))
    if not found:
        return ValueShape(form="literal", references=(), length=len(text))
    stripped = _PLACEHOLDER.sub("", text)
    form = "reference" if not stripped else "mixed"
    return ValueShape(form=form, references=found, length=len(text))


def _env_entries(raw: object) -> tuple[EnvEntry, ...]:
    if not isinstance(raw, dict):
        return ()
    return tuple(EnvEntry(key=str(k), shape=shape_of(v)) for k, v in raw.items())


def _str_or_none(raw: object) -> str | None:
    return raw if isinstance(raw, str) else None


def _server_entry(name: str, raw: object) -> ServerEntry:
    """Read one server entry, tolerating a shape that is not an object.

    A non-object entry is a malformed config rather than a reason to stop: it is
    recorded as a server that declares nothing, so the file's other servers are
    still reported and the broken one is still visible.
    """
    if not isinstance(raw, dict):
        return ServerEntry(
            name=name,
            declared_type=None,
            command=None,
            args=(),
            env=(),
            env_file=None,
            cwd=None,
            url=None,
            header_names=(),
            unmodelled=frozenset(),
        )
    args_raw = raw.get("args")
    headers_raw = raw.get("headers")
    return ServerEntry(
        name=name,
        declared_type=_str_or_none(raw.get("type")),
        command=_str_or_none(raw.get("command")),
        args=tuple(str(a) for a in args_raw) if isinstance(args_raw, list) else (),
        env=_env_entries(raw.get("env")),
        env_file=_str_or_none(raw.get("envFile")),
        cwd=_str_or_none(raw.get("cwd")),
        url=_str_or_none(raw.get("url")),
        header_names=tuple(str(h) for h in headers_raw) if isinstance(headers_raw, dict) else (),
        unmodelled=frozenset(raw) - _MODELLED_SERVER_KEYS,
    )


def _input_decls(raw: object) -> tuple[InputDecl, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[InputDecl] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        out.append(
            InputDecl(
                input_id=str(item.get("id", "")),
                kind=str(item.get("type", "")),
                is_password=item.get("password") is True,
                command=_str_or_none(item.get("command")),
            )
        )
    return tuple(out)


def _unreadable(source: HostConfig, reason: str) -> Inventory:
    return Inventory(
        source=source,
        dialect=None,
        servers=(),
        inputs=(),
        unmodelled_top_level=frozenset(),
        unreadable=reason,
    )


def read(source: HostConfig, text: str | None = None) -> Inventory:
    """Normalise one located config.

    `text` is accepted so a caller that already holds the file - or a test - can
    avoid a second read; when omitted the file named by `source.resolved` is
    read. The resolved path is used rather than the declared one because that is
    the file the host will actually open.
    """
    if text is None:
        if not source.exists:
            return _unreadable(source, "file does not exist")
        try:
            text = source.resolved.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return _unreadable(source, f"could not be read: {exc.strerror or exc}")

    try:
        parsed: Any = json.loads(_drop_trailing_commas(_strip_comments(text)))
    except json.JSONDecodeError as exc:
        return _unreadable(source, f"not valid JSON or JSONC: {exc.msg} at line {exc.lineno}")

    if not isinstance(parsed, dict):
        return _unreadable(source, f"top level is {type(parsed).__name__}, not an object")

    dialect = next((k for k in SERVER_MAP_KEYS if isinstance(parsed.get(k), dict)), None)
    raw_servers: Mapping[str, object] = parsed[dialect] if dialect is not None else {}
    known_top = set(SERVER_MAP_KEYS) | {"inputs"}
    return Inventory(
        source=source,
        dialect=dialect,
        servers=tuple(_server_entry(str(n), e) for n, e in raw_servers.items()),
        inputs=_input_decls(parsed.get("inputs")),
        unmodelled_top_level=frozenset(parsed) - known_top,
        unreadable=None,
    )
