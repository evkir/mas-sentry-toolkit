# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detect metadata tampering: invisible / mismatched / contradictory tool fields."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ..client import ToolDef


@dataclass(frozen=True, slots=True)
class TamperFinding:
    tool: str
    category: str
    detail: str


_BIDI_OVERRIDES = {"LRE", "RLE", "PDF", "LRO", "RLO", "LRI", "RLI", "FSI", "PDI"}

# (name_verb, description_verb_stem). Stems match common inflections via \b-anchored
# prefix: 'writ' -> write/writes/writing/written; 'delet' -> delete/deleted; etc.
# Word-boundary on the left prevents substring noise (e.g. 'get' inside 'target').
_VERB_MISMATCH = [
    ("read", "writ"),
    ("get", "delet"),
    ("list", "execut"),
    ("status", "shutdown"),
]


def _name_has(name_l: str, verb: str) -> bool:
    return re.search(rf"\b{verb}", name_l) is not None


def _desc_has(desc_l: str, stem: str) -> bool:
    return re.search(rf"\b{stem}", desc_l) is not None


def detect_metadata_tampering(tool: ToolDef) -> list[TamperFinding]:
    out: list[TamperFinding] = []

    if any(unicodedata.bidirectional(ch) in _BIDI_OVERRIDES for ch in tool.description):
        out.append(TamperFinding(tool.name, "bidi-override", "Bidirectional override in description"))

    name_l = tool.name.lower()
    desc_l = tool.description.lower()
    for name_verb, desc_stem in _VERB_MISMATCH:
        if _name_has(name_l, name_verb) and _desc_has(desc_l, desc_stem):
            out.append(
                TamperFinding(
                    tool.name,
                    "verb-mismatch",
                    f"Name implies '{name_verb}' but description mentions '{desc_stem}*'",
                )
            )

    # Schema declares no params but description claims authenticated/admin.
    schema = tool.input_schema or {}
    if not (schema.get("properties") or {}) and re.search(r"\badmin", desc_l):
        out.append(TamperFinding(tool.name, "admin-no-args", "Admin-class tool declares no parameters"))

    return out
