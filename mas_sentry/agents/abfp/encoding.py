# SPDX-License-Identifier: AGPL-3.0-or-later
"""Heuristic payload encoding detector. Returns a label, not a guarantee."""

from __future__ import annotations

import base64
import re

_B64_RE = re.compile(rb"^[A-Za-z0-9+/=\r\n]+$")


def detect_encoding(payload: bytes) -> str:
    if not payload:
        return "empty"
    if payload[0:1] in (b"{", b"[") and _looks_json(payload):
        return "json"
    if payload[0:1] == b"<":
        return "xml"
    if _is_base64(payload):
        return "base64"
    # Try UTF-8 before binary heuristics — printable text shouldn't be classified as protobuf.
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None and text.isprintable():
        return "utf8"
    if _is_msgpack(payload):
        return "msgpack"
    if _is_cbor(payload):
        return "cbor"
    if _is_protobuf(payload):
        return "protobuf"
    if text is not None:
        return "utf8"
    return "binary"


def _looks_json(p: bytes) -> bool:
    try:
        import json

        json.loads(p)
        return True
    except (ValueError, TypeError):
        return False


def _is_base64(p: bytes) -> bool:
    if len(p) < 8 or len(p) % 4 != 0:
        return False
    if not _B64_RE.fullmatch(p):
        return False
    try:
        base64.b64decode(p, validate=True)
        return True
    except (ValueError, base64.binascii.Error):
        return False


def _is_msgpack(p: bytes) -> bool:
    return bool(p) and 0x80 <= p[0] <= 0xC6


def _is_cbor(p: bytes) -> bool:
    return bool(p) and (p[0] & 0xE0) in (0x80, 0xA0, 0xC0)


def _is_protobuf(p: bytes) -> bool:
    if len(p) < 2:
        return False
    # protobuf wire-format: tag is varint, lower 3 bits = wire type 0..5
    first = p[0]
    wire_type = first & 0x07
    return wire_type in (0, 1, 2, 5) and first >> 3 != 0
