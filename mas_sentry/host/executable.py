# SPDX-License-Identifier: AGPL-3.0-or-later
"""Judge the executable surface of a settings file read by `surface.read_surface`.

The reader records what a settings file asks the host to execute; this module
decides which of it is a finding and how serious. The split is R-1.7: the reader
knows the schema, this knows the threat.

What the severity turns on is not the scope alone. A hook in a repository file is
foreign, but a hook that fires only when the operator later drives a tool is less
exposed than one that runs the moment the folder opens. So two axes decide it:

- When the handler first runs. A `SessionStart` or `Setup` hook, or an
  `InstructionsLoaded` one, runs before the operator does anything in the
  session - every `SessionStart` matcher (`startup`, `resume`, `clear`,
  `compact`, `fork`) is a moment the session opens or resumes, so the matcher
  does not change this. Any other event fires later, once the agent is already
  being driven.
- What the handler does. `command`, `http` and `mcp_tool` run code or reach the
  network off the host; `prompt` and `agent` drive the model instead, which is
  a weaker primitive.

Neither trust nor a per-command prompt gates any of this. Once a folder is
trusted every hook runs silently (GHSA-ph6w-f82w-28w6), and a `claude -p` or SDK
run - any CI agent on a checkout - never shows the trust dialog at all, so a
repository hook runs there unprompted
(https://code.claude.com/docs/en/permissions, "What runs before you trust a
folder"). That is why a repository-scope hook is a finding on its own, not only
when some other condition holds.

Scope decides whether there is a finding at all:

- Repository `settings.json` arrives with a checkout from whoever wrote it, so
  its executable surface is judged in full.
- `settings.local.json` is normally the operator's own and is not committed -
  but the host treats it as repository-supplied when it is tracked in git or
  reached through a symlinked `.claude`. The symlink is known from discovery; a
  reader that ran git to test the other case would be executing the very class
  of repository-controlled code this audit reports (`core.fsmonitor` runs on
  the first git command), so a non-symlinked local file is reported once as
  unverified rather than parsed for a verdict.
- A user-scope file is the operator's own, but a file another writer can rewrite
  after approval makes that approval persistent for them (CVE-2025-54136), and
  nothing in the file distinguishes the operator's hook from an implanted one.
  It is surfaced for a responder to read, without a verdict the data cannot
  support.

No raw value is read here: the reader already reduced every command, URL and
prompt to a shape, and this module judges shapes, origins and names only (R-7.3).
"""

from __future__ import annotations

from typing import Final

from mas_sentry.core.finding import Finding, Severity

from .discovery import HostConfig
from .surface import ExecutableSurface, HookHandler

# Events whose hooks run before the operator drives anything in the session.
# Source: https://code.claude.com/docs/en/hooks - SessionStart "when a session
# begins or resumes", Setup on --init/--maintenance, InstructionsLoaded when a
# CLAUDE.md or rules file loads. All three precede the first user action.
_ON_OPEN_EVENTS: Final = frozenset({"SessionStart", "Setup", "InstructionsLoaded"})

# Handler types that run code or reach off the host, as opposed to driving the
# model. Source: https://code.claude.com/docs/en/hooks handler reference.
_CODE_HANDLERS: Final = frozenset({"command", "http", "mcp_tool"})

_REFERENCES: Final = [
    "GHSA-ph6w-f82w-28w6",
    "CVE-2025-59536",
    "CVE-2025-54136",
    "https://code.claude.com/docs/en/permissions",
    "https://code.claude.com/docs/en/hooks",
]

_LOCAL_SETTINGS_NAME: Final = "settings.local.json"


def _hook_severity(hook: HookHandler) -> Severity:
    """Grade one repository-scope hook by when it runs and what it does."""
    if hook.handler_type not in _CODE_HANDLERS:
        # prompt / agent: drives the model, does not execute code off the host.
        return Severity.LOW
    return Severity.HIGH if hook.event in _ON_OPEN_EVENTS else Severity.MEDIUM


def _hook_finding(src: HostConfig, hook: HookHandler) -> Finding:
    when = "on session open, before any user action" if hook.event in _ON_OPEN_EVENTS else "when the agent runs a tool"
    does = {
        "command": "runs a shell command" if not hook.exec_form else "runs a command directly",
        "http": f"calls out to {hook.origin or 'an unparsed URL'}",
        "mcp_tool": "invokes an MCP tool",
        "prompt": "drives the model with a prompt",
        "agent": "drives a subagent with a prompt",
    }[hook.handler_type]
    return Finding(
        module="host.exec_hook",
        title=f"{src.host} ({src.scope}): {hook.event} hook {does}",
        detail=(
            f"{src.path} binds a {hook.handler_type} handler to {hook.event}; it {does} {when}. "
            "The file arrives with a checkout, and the host runs the handler without a per-command prompt "
            "once the folder is trusted and without any prompt at all in a claude -p or SDK run, so the "
            "author of the repository chooses what executes. The command is recorded as a shape only"
        ),
        severity=_hook_severity(hook),
        target=str(src.path),
        tags=["host", "exec_hook", hook.handler_type],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "path": str(src.path),
            "event": hook.event,
            "matcher": hook.matcher,
            "handler_type": hook.handler_type,
            "runs_on_open": hook.event in _ON_OPEN_EVENTS,
            "exec_form": hook.exec_form,
            "origin": hook.origin,
            "payload_form": hook.payload.form,
            "payload_references": list(hook.payload.references),
            "allowed_env_vars": list(hook.env_names),
        },
        references=_REFERENCES,
    )


def _helper_finding(src: HostConfig, key: str) -> Finding:
    return Finding(
        module="host.exec_helper",
        title=f"{src.host} ({src.scope}): {key} runs a command from the repository",
        detail=(
            f"{src.path} sets {key}, which names a command the host runs for its own purposes rather than "
            "as a hook the operator reasons about. A detector that watched hooks alone would be bypassed by "
            "moving the command here. The file arrives with a checkout and the command is recorded as a "
            "shape only"
        ),
        severity=Severity.HIGH,
        target=str(src.path),
        tags=["host", "exec_helper"],
        evidence={"host": src.host, "scope": src.scope, "path": str(src.path), "key": key},
        references=_REFERENCES,
    )


def _disable_finding(src: HostConfig) -> Finding:
    return Finding(
        module="host.exec_hook",
        title=f"{src.host} ({src.scope}): disableAllHooks=false re-enables hooks the operator turned off",
        detail=(
            f"{src.path} sets disableAllHooks to false. The host resolves the key by settings precedence, so "
            "a repository's false overrides a true the operator set in their own settings, turning their own "
            "kill switch off for this checkout"
        ),
        severity=Severity.MEDIUM,
        target=str(src.path),
        tags=["host", "exec_hook"],
        evidence={"host": src.host, "scope": src.scope, "path": str(src.path), "disable_all_hooks": False},
        references=_REFERENCES,
    )


def _unverified_local_finding(src: HostConfig) -> Finding:
    return Finding(
        module="host.exec_unverified",
        title=f"{src.host} ({src.scope}): local settings carry executable surface, tracking unverified",
        detail=(
            f"{src.path} is the local override, normally the operator's own and not committed. It carries "
            "hooks or helper commands, which the host runs as repository-supplied when the file is tracked in "
            "git or reached through a symlinked .claude. Whether it is committed was not tested, because the "
            "first git command in a repository can itself run repository-controlled code; treat the surface "
            "as repository-supplied if the file is committed"
        ),
        severity=Severity.INFO,
        target=str(src.path),
        tags=["host", "exec_unverified"],
        evidence={"host": src.host, "scope": src.scope, "path": str(src.path), "via_symlink": src.via_symlink},
        references=_REFERENCES,
    )


def _user_scope_finding(src: HostConfig, surface: ExecutableSurface) -> Finding:
    return Finding(
        module="host.exec_user",
        title=f"{src.host} ({src.scope}): executable surface on the operator's own machine",
        detail=(
            f"{src.path} carries {len(surface.hooks)} hook handler(s) and {len(surface.helpers)} helper "
            "command(s) in user scope. This is the operator's own file, but a file a second writer can rewrite "
            "after approval makes that approval persistent for them, and nothing in the file tells an "
            "operator's hook from an implanted one. Recorded for review, not as a verdict"
        ),
        severity=Severity.INFO,
        target=str(src.path),
        tags=["host", "exec_user"],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "path": str(src.path),
            "hooks": len(surface.hooks),
            "helpers": len(surface.helpers),
        },
        references=_REFERENCES,
    )


def surface_findings(src: HostConfig, surface: ExecutableSurface) -> list[Finding]:
    """Turn one file's executable surface into findings, graded by scope and timing.

    A file with no hooks and no helper commands produces nothing: its inventory
    row already states that it was read and found empty.
    """
    if not surface.hooks and not surface.helpers:
        return []

    if src.scope == "user":
        return [_user_scope_finding(src, surface)]

    is_local = src.path.name == _LOCAL_SETTINGS_NAME
    if is_local and not src.via_symlink:
        return [_unverified_local_finding(src)]

    out = [_hook_finding(src, h) for h in surface.hooks]
    out.extend(_helper_finding(src, c.key) for c in surface.helpers)
    if surface.disable_all_hooks is False:
        out.append(_disable_finding(src))
    return out
