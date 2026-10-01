# SPDX-License-Identifier: AGPL-3.0-or-later
"""Normalising the four config dialects into one inventory.

The fixtures below are the shapes the hosts actually document, not shapes
invented to suit the reader: VS Code keys on `servers` and declares `inputs`,
Cursor requires `type` on a local server and marks a remote one by `url`,
Claude Desktop states neither.
"""

from __future__ import annotations

import json
from pathlib import Path

from mas_sentry.host import HostConfig, Inventory, locate, read, shape_of


def _source(tmp_path: Path, name: str = "mcp.json", *, body: str | None = None) -> HostConfig:
    """A HostConfig pointing at a real file, produced by the real locator."""
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True, exist_ok=True)
    target = home / ".cursor" / name
    if body is not None:
        target.write_text(body)
    configs = locate(home=home, project_root=tmp_path / "repo", system="Linux")
    return next(c for c in configs if c.host == "cursor" and c.scope == "user")


def _read(tmp_path: Path, body: str) -> Inventory:
    return read(_source(tmp_path, body=body))


# --- dialects ---------------------------------------------------------------


def test_claude_dialect_keys_on_mcp_servers(tmp_path: Path) -> None:
    inv = _read(
        tmp_path,
        json.dumps({"mcpServers": {"git": {"command": "uvx", "args": ["mcp-server-git"]}}}),
    )
    assert inv.unreadable is None
    assert inv.dialect == "mcpServers"
    assert [s.name for s in inv.servers] == ["git"]
    assert inv.servers[0].command == "uvx"
    assert inv.servers[0].args == ("mcp-server-git",)


def test_vscode_dialect_keys_on_servers(tmp_path: Path) -> None:
    inv = _read(
        tmp_path,
        json.dumps({"servers": {"fetch": {"type": "http", "url": "https://example.test/mcp"}}}),
    )
    assert inv.dialect == "servers"
    assert inv.servers[0].declared_type == "http"
    assert inv.servers[0].url == "https://example.test/mcp"


def test_a_missing_type_is_not_guessed(tmp_path: Path) -> None:
    """Claude Desktop declares no transport, and the inventory must not invent one.

    Inferring "stdio because there is a command" would hide that the file never
    said so, and the gap between what a config declares and what the host does
    with it is where this operation's findings live.
    """
    inv = _read(tmp_path, json.dumps({"mcpServers": {"x": {"command": "node"}}}))
    assert inv.servers[0].declared_type is None
    assert inv.servers[0].command == "node"
    assert inv.servers[0].url is None


def test_a_server_declaring_both_command_and_url_keeps_both(tmp_path: Path) -> None:
    """A malformed entry stays malformed in the reading rather than being resolved."""
    inv = _read(tmp_path, json.dumps({"mcpServers": {"x": {"command": "node", "url": "https://a.test"}}}))
    assert inv.servers[0].command == "node"
    assert inv.servers[0].url == "https://a.test"


# --- values are shapes, never content ---------------------------------------


def test_a_literal_env_value_is_shaped_not_stored(tmp_path: Path) -> None:
    secret = "sk-ant-0123456789abcdef0123456789abcdef"
    inv = _read(tmp_path, json.dumps({"mcpServers": {"x": {"env": {"ANTHROPIC_API_KEY": secret}}}}))
    entry = inv.servers[0].env[0]
    assert entry.key == "ANTHROPIC_API_KEY"
    assert entry.shape.form == "literal"
    assert entry.shape.length == len(secret)
    assert entry.shape.references == ()
    # The guarantee: the value is nowhere in the inventory, at any depth.
    assert secret not in json.dumps(inv, default=str)


def test_an_input_reference_is_the_safe_shape(tmp_path: Path) -> None:
    """`${input:api-key}` is the pattern a host offers so the secret is never stored.

    It must not read as a literal, or the secret detector fires on exactly the
    configs that did the right thing (R-2.4).
    """
    inv = _read(tmp_path, json.dumps({"servers": {"x": {"env": {"KEY": "${input:api-key}"}}}}))
    shape = inv.servers[0].env[0].shape
    assert shape.form == "reference"
    assert shape.references == ("input:api-key",)


def test_a_partly_literal_value_reads_as_mixed(tmp_path: Path) -> None:
    inv = _read(tmp_path, json.dumps({"mcpServers": {"x": {"env": {"AUTH": "Bearer ${env:TOKEN}"}}}}))
    shape = inv.servers[0].env[0].shape
    assert shape.form == "mixed"
    assert shape.references == ("env:TOKEN",)


def test_an_empty_value_is_distinguished_from_a_literal(tmp_path: Path) -> None:
    inv = _read(tmp_path, json.dumps({"mcpServers": {"x": {"env": {"EMPTY": ""}}}}))
    assert inv.servers[0].env[0].shape.form == "empty"


def test_several_references_in_one_value_are_all_recorded(tmp_path: Path) -> None:
    shape = shape_of("${env:A}/${env:B}")
    assert shape.form == "mixed"
    assert shape.references == ("env:A", "env:B")


def test_a_non_string_value_is_shaped_as_a_literal() -> None:
    """A number or object in env carries no placeholder and is no more ours to keep."""
    assert shape_of(8080).form == "literal"
    assert shape_of({"nested": "thing"}).form == "literal"


def test_an_unclosed_placeholder_does_not_run_to_the_end_of_the_file() -> None:
    """The bound that keeps one broken brace from swallowing the document."""
    shape = shape_of("${" + "x" * 500)
    assert shape.form == "literal"
    assert shape.references == ()


def test_header_names_are_kept_and_header_values_are_not(tmp_path: Path) -> None:
    """A header value on a remote server is a bearer token."""
    token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    inv = _read(
        tmp_path,
        json.dumps({"servers": {"x": {"url": "https://a.test", "headers": {"Authorization": token}}}}),
    )
    assert inv.servers[0].header_names == ("Authorization",)
    assert token not in json.dumps(inv, default=str)


# --- inputs -----------------------------------------------------------------


def test_a_password_input_is_marked(tmp_path: Path) -> None:
    inv = _read(
        tmp_path,
        json.dumps(
            {
                "servers": {"x": {"type": "stdio", "command": "node"}},
                "inputs": [{"type": "promptString", "id": "api-key", "description": "Key", "password": True}],
            }
        ),
    )
    assert inv.inputs[0].input_id == "api-key"
    assert inv.inputs[0].kind == "promptString"
    assert inv.inputs[0].is_password is True


def test_a_command_input_records_what_it_runs(tmp_path: Path) -> None:
    """An input of kind `command` produces its value by running something."""
    inv = _read(
        tmp_path,
        json.dumps({"servers": {}, "inputs": [{"type": "command", "id": "v", "command": "shell.get"}]}),
    )
    assert inv.inputs[0].kind == "command"
    assert inv.inputs[0].command == "shell.get"


# --- nothing is dropped silently (R-2.1) ------------------------------------


def test_an_unmodelled_server_key_is_listed_not_ignored(tmp_path: Path) -> None:
    """A host adding a field becomes visible instead of invisible."""
    inv = _read(
        tmp_path,
        json.dumps({"mcpServers": {"x": {"command": "node", "auth": {"CLIENT_SECRET": "s"}, "dev": {}}}}),
    )
    assert inv.servers[0].unmodelled == frozenset({"auth", "dev"})


def test_an_unmodelled_top_level_key_is_listed(tmp_path: Path) -> None:
    """Claude Code nests per-project server maps under a key this reader does not model.

    Listing it means the file reports as partly unread rather than as a file
    with no servers in it.
    """
    inv = _read(
        tmp_path,
        json.dumps({"mcpServers": {}, "projects": {"/home/x": {"mcpServers": {"y": {}}}}}),
    )
    assert inv.unmodelled_top_level == frozenset({"projects"})


def test_a_malformed_file_states_why_rather_than_reporting_no_servers(tmp_path: Path) -> None:
    inv = _read(tmp_path, '{"mcpServers": {')
    assert inv.servers == ()
    assert inv.unreadable is not None
    assert "not valid JSON" in inv.unreadable


def test_an_absent_file_states_why(tmp_path: Path) -> None:
    inv = read(_source(tmp_path))
    assert inv.unreadable == "file does not exist"


def test_a_non_object_input_entry_does_not_lose_the_others(tmp_path: Path) -> None:
    inv = _read(
        tmp_path,
        json.dumps({"servers": {}, "inputs": ["nonsense", {"type": "promptString", "id": "k"}]}),
    )
    assert [i.input_id for i in inv.inputs] == ["k"]


def test_a_config_that_cannot_be_opened_states_why(tmp_path: Path) -> None:
    """A config present but unreadable is the condition O-2/c5 reports on.

    It must not collapse into "no servers". The fixture makes the config path a
    directory, which raises the same OSError family as a permission denial and
    does so for any user, including root in a container.
    """
    home = tmp_path / "home"
    (home / ".cursor" / "mcp.json").mkdir(parents=True)
    source = next(
        c
        for c in locate(home=home, project_root=tmp_path / "repo", system="Linux")
        if c.host == "cursor" and c.scope == "user"
    )
    inv = read(source)
    assert inv.servers == ()
    assert inv.unreadable is not None
    assert "could not be read" in inv.unreadable


def test_a_file_declaring_no_servers_is_not_an_error(tmp_path: Path) -> None:
    """The distinction a report must preserve: declares nothing vs could not be read."""
    inv = _read(tmp_path, json.dumps({"mcpServers": {}}))
    assert inv.servers == ()
    assert inv.unreadable is None
    assert inv.dialect == "mcpServers"


def test_a_top_level_array_is_reported_as_the_wrong_shape(tmp_path: Path) -> None:
    inv = _read(tmp_path, "[]")
    assert inv.unreadable is not None
    assert "not an object" in inv.unreadable


def test_a_non_object_server_entry_does_not_lose_the_others(tmp_path: Path) -> None:
    inv = _read(tmp_path, json.dumps({"mcpServers": {"broken": "nonsense", "good": {"command": "node"}}}))
    assert [s.name for s in inv.servers] == ["broken", "good"]
    assert inv.servers[0].command is None
    assert inv.servers[1].command == "node"


# --- JSONC tolerance --------------------------------------------------------


def test_a_comment_does_not_make_a_vscode_config_malformed(tmp_path: Path) -> None:
    """VS Code reads .vscode/mcp.json as JSONC, so this file is valid input."""
    inv = _read(
        tmp_path,
        """{
  // the fetch server
  "servers": {
    /* block comment */
    "fetch": { "type": "http", "url": "https://example.test/mcp" }
  }
}""",
    )
    assert inv.unreadable is None
    assert inv.servers[0].url == "https://example.test/mcp"


def test_a_double_slash_inside_a_url_is_not_a_comment(tmp_path: Path) -> None:
    """The case that makes the comment scan track string state."""
    inv = _read(tmp_path, '{"servers": {"x": {"url": "https://example.test/mcp"}}}')
    assert inv.servers[0].url == "https://example.test/mcp"


def test_a_trailing_comma_is_tolerated(tmp_path: Path) -> None:
    inv = _read(tmp_path, '{"mcpServers": {"x": {"command": "node", "args": ["a",],},},}')
    assert inv.unreadable is None
    assert inv.servers[0].args == ("a",)


def test_a_genuinely_unbalanced_document_is_still_rejected(tmp_path: Path) -> None:
    """Tolerating trailing commas must not turn into tolerating a truncated file.

    This fixture is the previous one with a closing brace missing - the shape a
    half-written config has - and it has to stay unreadable.
    """
    inv = _read(tmp_path, '{"mcpServers": {"x": {"command": "node", "args": ["a",],},}')
    assert inv.unreadable is not None


def test_a_trailing_comma_before_a_comment_is_tolerated(tmp_path: Path) -> None:
    """Why trailing commas are a second pass: the brace may be behind a comment."""
    inv = _read(
        tmp_path,
        """{
  "mcpServers": {
    "x": { "command": "node" }, // note
  }
}""",
    )
    assert inv.unreadable is None
    assert inv.servers[0].command == "node"


def test_a_comma_inside_a_string_value_survives(tmp_path: Path) -> None:
    """`{"a": "x, }"}` is a valid document whose value contains that sequence.

    A blind substitution would rewrite the operator's data, so the trailing-comma
    pass tracks string state too.
    """
    inv = _read(tmp_path, json.dumps({"mcpServers": {"x": {"cwd": "weird, }"}}}))
    assert inv.servers[0].cwd == "weird, }"


def test_an_escaped_quote_does_not_desynchronise_the_scan(tmp_path: Path) -> None:
    inv = _read(tmp_path, json.dumps({"mcpServers": {"x": {"cwd": 'has " quote'}}}))
    assert inv.servers[0].cwd == 'has " quote'


# --- the source travels with the reading ------------------------------------


def test_the_inventory_carries_the_config_it_came_from(tmp_path: Path) -> None:
    """A finding has to name the file, and the scope decides how much it matters."""
    inv = _read(tmp_path, json.dumps({"mcpServers": {}}))
    assert inv.source.host == "cursor"
    assert inv.source.scope == "user"


def test_text_may_be_supplied_instead_of_read_from_disk(tmp_path: Path) -> None:
    source = _source(tmp_path)
    inv = read(source, text=json.dumps({"mcpServers": {"x": {"command": "node"}}}))
    assert inv.unreadable is None
    assert inv.servers[0].command == "node"
