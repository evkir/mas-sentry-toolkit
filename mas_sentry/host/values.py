# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shape of a config value, never its content.

Separated from the readers so that each of them - the server inventory and the
executable-settings surface - classifies values the same way without importing
the other. A value is reduced here before it reaches any dataclass a report is
built from, which is what puts "no secret leaves the host" in the type rather
than in a filter (R-7.3).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Final

# `${...}` placeholder. The body is bounded: a config is operator-supplied text,
# and an unclosed brace in a minified one-line file would otherwise let one
# placeholder run to the end of the document.
_PLACEHOLDER: Final = re.compile(r"\$\{([^}]{0,200})\}")


@dataclass(frozen=True, slots=True)
class ValueShape:
    """What a config value is, never what it says.

    `form` is one of: `empty`, `reference` (the whole value is one placeholder),
    `mixed` (placeholders plus other text), `literal` (no placeholder at all).
    `length` is the raw value's length, which lets a report distinguish a short
    flag from something key-shaped without carrying either.
    """

    form: str
    references: tuple[str, ...]
    length: int


def shape_of(value: object) -> ValueShape:
    """Classify a config value without keeping it.

    A non-string value (a number, a bool, a nested object) is reported as a
    literal of its rendered length: it carries no placeholder, and its content
    is no more ours to keep than a string's.
    """
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    if not text:
        return ValueShape(form="empty", references=(), length=0)
    found = tuple(m.group(1) for m in _PLACEHOLDER.finditer(text))
    if not found:
        return ValueShape(form="literal", references=(), length=len(text))
    stripped = _PLACEHOLDER.sub("", text)
    form = "reference" if not stripped else "mixed"
    return ValueShape(form=form, references=found, length=len(text))
