# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read MCP CallToolResult payloads: content blocks and tool-level errors.

Two protocol facts drive this module, and missing either one costs detections.

First, MCP splits errors in two. A malformed request or an unknown tool comes
back as a JSON-RPC error, but anything the tool itself raises is reported inside
a *successful* response as `isError: true` with the explanation in the content
blocks - deliberately, so the model can see the failure and self-correct. A
probe that only inspects the JSON-RPC error field therefore cannot tell a server
that firmly refused its payload from one that answered with nothing useful. The
refusal is the interesting half: it proves the parameter exists and is guarded.

Second, a tool result is a list of typed content blocks, not a string. Text
lives under `text`; images and audio arrive base64-encoded under `data`; an
embedded resource nests its own text or blob. Stringifying the raw result object
yields a Python repr in which the dict scaffolding crowds out the payload under
any truncation, and base64 blocks hide their contents from substring matching
entirely - the same class of false negative that the A2A artifact reader closed.

Extraction here decodes what a reader would actually see, so indicator matching
and exfiltration scanning operate on real content.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterator
from typing import Any


def is_tool_error(result: Any) -> bool:
    """True when a successful JSON-RPC response carries a tool-level failure."""
    return isinstance(result, dict) and result.get("isError") is True


def _decode_base64(raw: str) -> str:
    """Best-effort base64 -> utf-8 text; empty string when not decodable as text."""
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def extract_block_text(block: Any) -> str:
    """Readable text carried by one content block, decoded where needed.

    Order follows the spec block types: text, then inline base64 payloads for
    image and audio blocks, then an embedded resource which nests either its own
    text or a base64 blob. A resource link contributes its URI, since a scanner
    does not dereference it.
    """
    if not isinstance(block, dict):
        return ""
    text = block.get("text")
    if isinstance(text, str):
        return text
    data = block.get("data")
    if isinstance(data, str):
        return _decode_base64(data)
    resource = block.get("resource")
    if isinstance(resource, dict):
        nested = resource.get("text")
        if isinstance(nested, str):
            return nested
        blob = resource.get("blob")
        if isinstance(blob, str):
            return _decode_base64(blob)
        uri = resource.get("uri")
        if isinstance(uri, str):
            return uri
    uri = block.get("uri")
    if isinstance(uri, str):
        return uri
    return ""


def iter_content_texts(result: Any) -> Iterator[str]:
    """Yield the decoded text of every content block in a tool result."""
    if not isinstance(result, dict):
        return
    blocks = result.get("content")
    if not isinstance(blocks, list):
        return
    for block in blocks:
        yield extract_block_text(block)


def tool_result_text(result: Any) -> str:
    """Concatenate the decoded text of a tool result, newline-joined.

    Falls back to a JSON dump of the result when it carries no recognisable
    content blocks, so a non-conforming server still yields something to match
    against instead of silently scanning an empty string.
    """
    joined = "\n".join(t for t in iter_content_texts(result) if t)
    if joined:
        return joined
    if isinstance(result, dict) and "content" in result:
        return ""
    try:
        return json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(result)
