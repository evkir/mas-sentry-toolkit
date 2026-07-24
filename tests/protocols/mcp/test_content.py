# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for MCP CallToolResult content extraction and tool-error detection."""

from __future__ import annotations

import base64

from mas_sentry.protocols.mcp.content import (
    extract_block_text,
    is_tool_error,
    iter_content_texts,
    tool_result_text,
)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# --- tool-level errors ---


def test_is_tool_error_true() -> None:
    assert is_tool_error({"content": [{"type": "text", "text": "denied"}], "isError": True})


def test_is_tool_error_false_when_absent_or_false() -> None:
    assert not is_tool_error({"content": []})
    assert not is_tool_error({"content": [], "isError": False})


def test_is_tool_error_ignores_non_dict() -> None:
    assert not is_tool_error("boom")
    assert not is_tool_error(None)


# --- content blocks ---


def test_text_block() -> None:
    assert extract_block_text({"type": "text", "text": "root:x:0:0"}) == "root:x:0:0"


def test_image_block_is_decoded() -> None:
    # The false-negative case: a substring match against the raw result never
    # sees content that arrives base64-encoded.
    block = {"type": "image", "data": _b64("root:x:0:0"), "mimeType": "image/png"}
    assert extract_block_text(block) == "root:x:0:0"


def test_audio_block_is_decoded() -> None:
    assert extract_block_text({"type": "audio", "data": _b64("spoken")}) == "spoken"


def test_undecodable_data_yields_empty() -> None:
    assert extract_block_text({"type": "image", "data": "!!!not-base64!!!"}) == ""
    assert extract_block_text({"type": "image", "data": base64.b64encode(b"\xff\xfe").decode()}) == ""


def test_embedded_resource_text() -> None:
    block = {"type": "resource", "resource": {"uri": "file:///etc/passwd", "text": "root:x"}}
    assert extract_block_text(block) == "root:x"


def test_embedded_resource_blob_is_decoded() -> None:
    block = {"type": "resource", "resource": {"uri": "file:///x", "blob": _b64("secret")}}
    assert extract_block_text(block) == "secret"


def test_embedded_resource_falls_back_to_uri() -> None:
    block = {"type": "resource", "resource": {"uri": "file:///etc/shadow"}}
    assert extract_block_text(block) == "file:///etc/shadow"


def test_resource_link_contributes_uri() -> None:
    assert extract_block_text({"type": "resource_link", "uri": "https://x.test/a"}) == "https://x.test/a"


def test_unknown_and_malformed_blocks_are_empty() -> None:
    assert extract_block_text({"type": "mystery"}) == ""
    assert extract_block_text("not a block") == ""
    assert extract_block_text(None) == ""


# --- whole results ---


def test_iter_walks_blocks_in_order() -> None:
    result = {"content": [{"type": "text", "text": "a"}, {"type": "image", "data": _b64("b")}]}
    assert list(iter_content_texts(result)) == ["a", "b"]


def test_iter_ignores_bad_shapes() -> None:
    assert list(iter_content_texts({"content": "not-a-list"})) == []
    assert list(iter_content_texts(["not", "a", "dict"])) == []


def test_tool_result_text_joins_and_drops_empty() -> None:
    result = {"content": [{"type": "text", "text": "a"}, {"type": "mystery"}, {"type": "text", "text": "b"}]}
    assert tool_result_text(result) == "a\nb"


def test_empty_content_list_yields_empty_string() -> None:
    assert tool_result_text({"content": []}) == ""


def test_non_conforming_result_falls_back_to_json() -> None:
    # A server that ignores the content-block shape still has to be matchable.
    assert tool_result_text({"stdout": "root:x:0:0"}) == '{"stdout": "root:x:0:0"}'


def test_unserialisable_result_falls_back_to_str() -> None:
    assert tool_result_text({"k": object()}).startswith("{'k': <object")


def test_top_level_blob_is_decoded() -> None:
    # resources/read returns ResourceContents with a top-level text or blob,
    # not a typed content block.
    assert extract_block_text({"uri": "file:///x", "blob": _b64("payload")}) == "payload"


def test_top_level_text_wins_over_blob() -> None:
    assert extract_block_text({"uri": "file:///x", "text": "plain", "blob": _b64("other")}) == "plain"
