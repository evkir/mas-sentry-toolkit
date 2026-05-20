# SPDX-License-Identifier: AGPL-3.0-or-later
"""Infer a minimal type-shape schema from JSON payloads (no genson dep)."""

from __future__ import annotations

import json
from typing import Any


def infer_schema(payloads: list[bytes]) -> dict[str, Any]:
    """
    Produce a lightweight schema:
    {"type": "object", "keys": {k: "<observed-types>"}, "samples": N}
    Returns {} if payloads aren't JSON.
    """
    sample_types: dict[str, set[str]] = {}
    parsed = 0
    for raw in payloads:
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            continue
        parsed += 1
        _walk("", obj, sample_types)
    if parsed == 0:
        return {}
    return {
        "type": "object",
        "samples": parsed,
        "keys": {k: sorted(v) for k, v in sample_types.items()},
    }


def _walk(prefix: str, obj: Any, acc: dict[str, set[str]]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            acc.setdefault(path, set()).add(_jstype(v))
            _walk(path, v, acc)
    elif isinstance(obj, list) and obj:
        acc.setdefault(f"{prefix}[]", set()).add(_jstype(obj[0]))
        _walk(f"{prefix}[]", obj[0], acc)


def _jstype(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "unknown"
