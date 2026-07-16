# SPDX-License-Identifier: AGPL-3.0-or-later
"""Extract human-readable text from A2A artifact Parts, across spec generations.

An A2A task returns artifacts, each composed of Parts. The probe layer needs
the text an agent actually emitted - to spot a canary echo that proves an
injected directive executed. Blindly str()-ing the raw artifact list misses the
payload whenever the agent returns it inside a file part\'s base64 content (the
canary is base64-encoded, so a substring match never fires) and adds noise from
metadata, media types, and URLs.

v1.0 redesigned Part into a single member-discriminated shape - `text`, `data`,
`url`, or `raw` (base64) - dropping the v0.3.x `kind` field and the nested
`file.fileWithBytes` / `file.fileWithUri`. Discrimination here is by member
presence, which covers both generations for text and data (the members exist
alongside the old `kind`); only the file shape differs, so both are read. The
result is decoded text, so canary detection sees what a human would.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterator
from typing import Any


def _decode_base64(raw: str) -> str:
    """Best-effort base64 -> utf-8 text; empty string if not decodable as text."""
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def extract_part_text(part: Any) -> str:
    """Text carried by one Part, v1.0 or v0.3.x, decoded where needed.

    Order: text, structured data (JSON-serialised so an embedded canary is
    still found), inline base64 bytes (decoded - the case a blunt str() misses),
    then a URI reference (its URL string; a passive scanner does not fetch it).
    Both the v1.0 flat shape and the v0.3.x nested `file` object are read.
    """
    if not isinstance(part, dict):
        return ""
    text = part.get("text")
    if isinstance(text, str):
        return text
    data = part.get("data")
    if isinstance(data, (dict, list)):
        return json.dumps(data, sort_keys=True)
    raw = part.get("raw")
    if isinstance(raw, str):
        return _decode_base64(raw)
    url = part.get("url")
    if isinstance(url, str):
        return url
    file = part.get("file")
    if isinstance(file, dict):
        inline = file.get("fileWithBytes") or file.get("bytes")
        if isinstance(inline, str):
            return _decode_base64(inline)
        uri = file.get("fileWithUri") or file.get("uri")
        if isinstance(uri, str):
            return uri
    return ""


def iter_artifact_texts(artifacts: list[dict[str, Any]]) -> Iterator[str]:
    """Yield the decoded text of every Part across a task\'s artifacts."""
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        parts = artifact.get("parts")
        if not isinstance(parts, list):
            continue
        for part in parts:
            yield extract_part_text(part)


def artifact_text(artifacts: list[dict[str, Any]]) -> str:
    """Concatenate the decoded text of all Parts across artifacts, newline-joined."""
    return "\n".join(t for t in iter_artifact_texts(artifacts) if t)
