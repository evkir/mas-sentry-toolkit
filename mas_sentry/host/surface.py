# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read what an agent settings file makes the host execute.

A Claude Code settings file runs code in two ways. `hooks` binds commands, HTTP
calls, MCP tool calls and model prompts to lifecycle events. Eight helper keys
(`apiKeyHelper`, `statusLine` and the rest) each name one command the host runs
for its own purposes. Both are honoured from a repository's
`.claude/settings.json`, the file that arrives with a checkout.

Sources:

- GHSA-ph6w-f82w-28w6: hooks in repository settings ran without a per-command
  prompt once the folder was trusted. The fix reworded the trust dialog; the
  behaviour itself is by design.
- CVE-2025-59536 (GHSA-4fgq-fpq9-mr3g): repository code ran before the trust
  dialog was accepted. Fixed in 1.0.111.
- https://code.claude.com/docs/en/permissions, "What runs before you trust a
  folder": hooks, the `env` block and helper commands are used without trust in
  `claude -p` and SDK sessions, which never show the dialog.
- https://code.claude.com/docs/en/hooks and /settings-reference for the shapes.

Hooks and helpers are read into one surface because a detector that watched
`hooks` alone would be bypassed by moving the same command into `statusLine`.

Like the server inventory, this records and does not judge: which event fires
before consent is the detector's question. Values are kept as shapes for the
same reason as there - a hook command or an HTTP hook URL can carry a token.
Every part of the structure that cannot be read becomes a stated gap rather
than a shorter list (R-2.1).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

from .values import ValueShape, shape_of

HELPER_KEYS: Final = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
    "statusLine",
    "subagentStatusLine",
    "fileSuggestion",
)
"""Settings keys that each name one command the host runs, per the settings reference."""

SURFACE_KEYS: Final = frozenset({"hooks", "disableAllHooks", *HELPER_KEYS})
"""Top-level keys this module reads; the inventory leaves them out of `unmodelled`."""

# The field that says what a handler runs, calls or sends, by handler type.
# A type outside this table is a gap: what it would execute is unknown, and
# recording it as a handler with an empty payload would read as harmless.
_PAYLOAD_FIELD: Final = {
    "command": "command",
    "http": "url",
    "mcp_tool": "tool",
    "prompt": "prompt",
    "agent": "prompt",
}

# Every handler field the hooks reference documents. A field outside this set
# is listed as unmodelled, which is how a new handler option becomes visible.
_HANDLER_KEYS: Final = frozenset(
    {
        "type",
        "command",
        "args",
        "shell",
        "async",
        "asyncRewake",
        "url",
        "headers",
        "allowedEnvVars",
        "server",
        "tool",
        "input",
        "prompt",
        "model",
        "if",
        "timeout",
        "statusMessage",
        "once",
    }
)


@dataclass(frozen=True, slots=True)
class HookHandler:
    """One handler under one event and matcher, as the file declares it.

    `matcher` is kept verbatim and is `None` when the group omits it; whether
    it narrows anything is the detector's call, made with the host's rules.
    `exec_form` is true when `args` is a list: the host spawns the command
    directly instead of handing the string to a shell. `origin` is the scheme
    and host an HTTP handler sends to, without path, query or credentials.
    """

    event: str
    matcher: str | None
    handler_type: str
    payload: ValueShape
    exec_form: bool
    origin: str | None
    env_names: tuple[str, ...]
    unmodelled: frozenset[str]


@dataclass(frozen=True, slots=True)
class HelperCommand:
    key: str
    payload: ValueShape


@dataclass(frozen=True, slots=True)
class ExecutableSurface:
    """Everything one settings file asks the host to execute.

    `disable_all_hooks` is `None` when the file does not declare the key. That
    is distinct from `False`: the host resolves the key by settings precedence,
    so a repository's `false` overrides an operator's user-scope `true`.
    """

    hooks: tuple[HookHandler, ...]
    helpers: tuple[HelperCommand, ...]
    disable_all_hooks: bool | None
    gaps: tuple[str, ...]


def _origin(url: str) -> str | None:
    # urlsplit raises on a malformed bracketed host, and this is untrusted text.
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        return None
    return f"{parts.scheme}://{host}" if parts.scheme and host else None


def _handler(event: str, matcher: str | None, raw: object, where: str) -> HookHandler | str:
    """Read one handler, or say where and why it could not be read.

    The reason never quotes the offending value: the guarantee that no config
    value reaches a report covers the malformed ones too.
    """
    if not isinstance(raw, dict):
        return f"{where}: {type(raw).__name__}, not an object"
    handler_type = raw.get("type")
    # Checked as a string first: a list here is unhashable and would raise on lookup.
    if not isinstance(handler_type, str) or handler_type not in _PAYLOAD_FIELD:
        return f"{where}: handler type is not one of {', '.join(_PAYLOAD_FIELD)}"
    field = _PAYLOAD_FIELD[handler_type]
    payload = raw.get(field)
    if not isinstance(payload, str):
        return f"{where}: {handler_type} handler has no '{field}' string"
    env_raw = raw.get("allowedEnvVars")
    return HookHandler(
        event=event,
        matcher=matcher,
        handler_type=handler_type,
        payload=shape_of(payload),
        exec_form=isinstance(raw.get("args"), list),
        origin=_origin(payload) if handler_type == "http" else None,
        env_names=tuple(str(v) for v in env_raw) if isinstance(env_raw, list) else (),
        unmodelled=frozenset(raw) - _HANDLER_KEYS,
    )


def _hooks(raw: object) -> tuple[list[HookHandler], list[str]]:
    """Walk event -> matcher group -> handler list, keeping every readable handler."""
    handlers: list[HookHandler] = []
    gaps: list[str] = []
    if not isinstance(raw, dict):
        return handlers, [f"hooks: {type(raw).__name__}, not an object"]
    for event, groups in raw.items():
        if not isinstance(groups, list):
            gaps.append(f"hooks.{event}: {type(groups).__name__}, not a list")
            continue
        for g, group in enumerate(groups):
            where = f"hooks.{event}[{g}]"
            matcher = group.get("matcher") if isinstance(group, dict) else None
            inner = group.get("hooks") if isinstance(group, dict) else None
            if not isinstance(inner, list) or not (matcher is None or isinstance(matcher, str)):
                gaps.append(f"{where}: not a matcher group with a handler list")
                continue
            for h, item in enumerate(inner):
                read = _handler(str(event), matcher, item, f"{where}.hooks[{h}]")
                if isinstance(read, str):
                    gaps.append(read)
                else:
                    handlers.append(read)
    return handlers, gaps


def read_surface(parsed: Mapping[str, object]) -> ExecutableSurface:
    """Read the executable keys of one parsed settings document."""
    handlers, gaps = _hooks(parsed["hooks"]) if "hooks" in parsed else ([], [])
    helpers: list[HelperCommand] = []
    for key in HELPER_KEYS:
        if key not in parsed:
            continue
        raw = parsed[key]
        # String helpers name the command; statusLine and its kin wrap it in
        # {"type": "command", "command": ...}.
        command = raw.get("command") if isinstance(raw, dict) else raw
        if isinstance(command, str):
            helpers.append(HelperCommand(key=key, payload=shape_of(command)))
        else:
            gaps.append(f"{key}: no command string")
    raw_disable = parsed.get("disableAllHooks")
    disable = raw_disable if isinstance(raw_disable, bool) else None
    if raw_disable is not None and disable is None:
        gaps.append(f"disableAllHooks: {type(raw_disable).__name__}, not a boolean")
    return ExecutableSurface(
        hooks=tuple(handlers),
        helpers=tuple(helpers),
        disable_all_hooks=disable,
        gaps=tuple(gaps),
    )
