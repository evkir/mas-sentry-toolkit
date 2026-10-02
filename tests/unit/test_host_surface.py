# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reading the executable surface of a Claude Code settings file.

Fixture shapes follow the hooks and settings references
(code.claude.com/docs/en/hooks, /settings-reference, /statusline): the three-level
event -> matcher group -> handler nesting, the five handler types, the string
helper keys and the `{"type": "command", "command": ...}` object ones.
"""

from __future__ import annotations

import json
from pathlib import Path

from mas_sentry.host import Inventory, locate, read
from mas_sentry.host.surface import HELPER_KEYS, read_surface

_CANARY = "canary-7f3a9e1c-value-must-not-survive"


def _settings(tmp_path: Path, doc: dict) -> Inventory:
    """Write repository settings and read them through the real locator."""
    target = tmp_path / "repo" / ".claude" / "settings.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(doc))
    configs = locate(home=tmp_path / "home", project_root=tmp_path / "repo", system="Linux")
    return read(next(c for c in configs if c.path == target))


def _hook(event: str, handler: dict, matcher: str | None = None) -> dict:
    group: dict = {"hooks": [handler]}
    if matcher is not None:
        group["matcher"] = matcher
    return {"hooks": {event: [group]}}


# --- hooks ------------------------------------------------------------------


def test_a_session_start_hook_is_read_with_its_event_and_matcher(tmp_path: Path) -> None:
    inv = _settings(tmp_path, _hook("SessionStart", {"type": "command", "command": "./bootstrap.sh"}, "startup"))
    assert inv.surface is not None
    (hook,) = inv.surface.hooks
    assert (hook.event, hook.matcher, hook.handler_type) == ("SessionStart", "startup", "command")
    assert hook.exec_form is False
    assert hook.payload.form == "literal"
    assert inv.surface.gaps == ()


def test_an_omitted_matcher_is_recorded_as_absent(tmp_path: Path) -> None:
    """Absent and narrowing are different answers to "does this fire on open"."""
    inv = _settings(tmp_path, _hook("SessionStart", {"type": "command", "command": "./bootstrap.sh"}))
    assert inv.surface is not None
    assert inv.surface.hooks[0].matcher is None


def test_exec_form_is_told_apart_from_shell_form(tmp_path: Path) -> None:
    """With `args` the host spawns directly; without it the string goes to a shell."""
    inv = _settings(tmp_path, _hook("Stop", {"type": "command", "command": "./notify", "args": ["--done"]}))
    assert inv.surface is not None
    assert inv.surface.hooks[0].exec_form is True


def test_every_documented_handler_type_is_read(tmp_path: Path) -> None:
    handlers = [
        {"type": "command", "command": "./lint.sh"},
        {"type": "http", "url": "https://hooks.example.test/in"},
        {"type": "mcp_tool", "server": "memory", "tool": "store"},
        {"type": "prompt", "prompt": "Check $ARGUMENTS"},
        {"type": "agent", "prompt": "Verify $ARGUMENTS"},
    ]
    inv = _settings(tmp_path, {"hooks": {"PostToolUse": [{"matcher": "Edit|Write", "hooks": handlers}]}})
    assert inv.surface is not None
    assert [h.handler_type for h in inv.surface.hooks] == ["command", "http", "mcp_tool", "prompt", "agent"]
    assert inv.surface.gaps == ()


def test_a_hook_command_is_shaped_not_stored(tmp_path: Path) -> None:
    """The guarantee is in the type: no field of the reading holds the text."""
    inv = _settings(tmp_path, _hook("SessionStart", {"type": "command", "command": f"./sync --token {_CANARY}"}))
    assert _CANARY not in repr(inv)
    assert inv.surface is not None
    assert inv.surface.hooks[0].payload.length == len(f"./sync --token {_CANARY}")


def test_an_http_hook_keeps_where_it_sends_and_nothing_it_sends(tmp_path: Path) -> None:
    handler = {
        "type": "http",
        "url": f"https://user:{_CANARY}@hooks.example.test:8443/in?k={_CANARY}",
        "headers": {"Authorization": f"Bearer {_CANARY}"},
        "allowedEnvVars": ["HOOK_TOKEN"],
    }
    inv = _settings(tmp_path, _hook("UserPromptSubmit", handler))
    assert _CANARY not in repr(inv)
    assert inv.surface is not None
    (hook,) = inv.surface.hooks
    assert hook.origin == "https://hooks.example.test"
    assert hook.env_names == ("HOOK_TOKEN",)


def test_a_url_that_does_not_parse_has_no_origin_and_does_not_raise(tmp_path: Path) -> None:
    inv = _settings(tmp_path, _hook("Stop", {"type": "http", "url": "http://[::1/in"}))
    assert inv.surface is not None
    assert inv.surface.hooks[0].origin is None


def test_a_reference_url_is_recorded_as_a_reference(tmp_path: Path) -> None:
    inv = _settings(tmp_path, _hook("Stop", {"type": "http", "url": "${HOOK_URL}"}))
    assert inv.surface is not None
    (hook,) = inv.surface.hooks
    assert (hook.payload.form, hook.payload.references, hook.origin) == ("reference", ("HOOK_URL",), None)


def test_an_undocumented_handler_field_is_listed(tmp_path: Path) -> None:
    inv = _settings(tmp_path, _hook("Stop", {"type": "command", "command": "./x", "runAs": "root"}))
    assert inv.surface is not None
    assert inv.surface.hooks[0].unmodelled == frozenset({"runAs"})


# --- helpers ----------------------------------------------------------------


def test_every_helper_key_is_read_in_its_documented_shape() -> None:
    """Five keys take a command string, three wrap it in a command object."""
    objects = {"statusLine", "subagentStatusLine", "fileSuggestion"}
    doc = {k: ({"type": "command", "command": f"./{k}.sh"} if k in objects else f"./{k}.sh") for k in HELPER_KEYS}
    surface = read_surface(doc)
    assert [c.key for c in surface.helpers] == list(HELPER_KEYS)
    assert all(c.payload.form == "literal" for c in surface.helpers)
    assert surface.gaps == ()


def test_a_helper_without_a_command_is_a_gap() -> None:
    surface = read_surface({"statusLine": {"type": "command", "padding": 2}, "apiKeyHelper": 7})
    assert surface.helpers == ()
    assert surface.gaps == ("apiKeyHelper: no command string", "statusLine: no command string")


# --- disableAllHooks --------------------------------------------------------


def test_disable_all_hooks_false_is_distinct_from_undeclared() -> None:
    """A repository's `false` overrides an operator's `true`; silence does not."""
    assert read_surface({"disableAllHooks": False}).disable_all_hooks is False
    assert read_surface({}).disable_all_hooks is None


def test_a_non_boolean_disable_all_hooks_is_a_gap() -> None:
    surface = read_surface({"disableAllHooks": "yes"})
    assert surface.disable_all_hooks is None
    assert surface.gaps == ("disableAllHooks: str, not a boolean",)


# --- gaps -------------------------------------------------------------------


def test_an_unreadable_part_is_a_gap_and_the_rest_is_still_read() -> None:
    doc = {
        "hooks": {
            "SessionStart": "./x.sh",
            "PreToolUse": [{"matcher": 3, "hooks": []}, {"matcher": "Bash"}],
            "Stop": [
                {
                    "hooks": [
                        {"type": "command", "command": "./ok.sh"},
                        5,
                        {"type": "shell", "command": "./y.sh"},
                        {"type": ["command"], "command": "./z.sh"},
                        {"type": "http"},
                    ]
                }
            ],
        }
    }
    surface = read_surface(doc)
    assert [h.payload.length for h in surface.hooks] == [len("./ok.sh")]
    assert surface.gaps == (
        "hooks.SessionStart: str, not a list",
        "hooks.PreToolUse[0]: not a matcher group with a handler list",
        "hooks.PreToolUse[1]: not a matcher group with a handler list",
        "hooks.Stop[0].hooks[1]: int, not an object",
        "hooks.Stop[0].hooks[2]: handler type is not one of command, http, mcp_tool, prompt, agent",
        "hooks.Stop[0].hooks[3]: handler type is not one of command, http, mcp_tool, prompt, agent",
        "hooks.Stop[0].hooks[4]: http handler has no 'url' string",
    )


def test_a_gap_never_quotes_the_value_it_could_not_read() -> None:
    surface = read_surface({"hooks": {"Stop": [{"hooks": [{"type": _CANARY, "command": _CANARY}]}]}})
    assert _CANARY not in repr(surface)


def test_hooks_that_are_not_an_object_are_a_gap() -> None:
    assert read_surface({"hooks": []}).gaps == ("hooks: list, not an object",)


# --- placement --------------------------------------------------------------


def test_surface_keys_leave_unmodelled_and_other_settings_stay(tmp_path: Path) -> None:
    """Every key this module reads leaves `unmodelled`; the rest stay listed there."""
    doc = {
        **_hook("Stop", {"type": "command", "command": "./x"}),
        "statusLine": "./s",
        "env": {"A": "b"},
        "enableAllProjectMcpServers": True,
        "permissions": {"allow": ["Bash"]},
    }
    inv = _settings(tmp_path, doc)
    assert inv.unmodelled_top_level == frozenset({"permissions"})


def test_a_server_config_is_not_read_for_hooks(tmp_path: Path) -> None:
    """A `hooks` key in a file the host never reads hooks from is not a hook."""
    target = tmp_path / "home" / ".cursor" / "mcp.json"
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"mcpServers": {}, **_hook("Stop", {"type": "command", "command": "./x"})}))
    configs = locate(home=tmp_path / "home", project_root=tmp_path / "repo", system="Linux")
    inv = read(next(c for c in configs if c.path == target))
    assert inv.surface is None
    assert "hooks" in inv.unmodelled_top_level


def test_an_empty_settings_file_has_an_empty_surface(tmp_path: Path) -> None:
    inv = _settings(tmp_path, {})
    assert inv.surface is not None
    assert (inv.surface.hooks, inv.surface.helpers, inv.surface.gaps) == ((), (), ())
