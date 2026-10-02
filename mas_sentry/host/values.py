# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shape of a config value, never its content.

A value is also classified here against the documented credential formats. The
classification has to happen in the reader rather than in a detector, because by
the time a detector sees a value it is already reduced to a shape - which is the
property that keeps a key out of a report, and is not worth giving up to let
something downstream re-examine the text. What leaves this module is a label
such as `prefix:ghp_` or `jwt`, never the characters that earned it.

Separated from the readers so that each of them - the server inventory and the
executable-settings surface - classifies values the same way without importing
the other. A value is reduced here before it reaches any dataclass a report is
built from, which is what puts "no secret leaves the host" in the type rather
than in a filter (R-7.3).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Final

# `${...}` placeholder. The body is bounded: a config is operator-supplied text,
# and an unclosed brace in a minified one-line file would otherwise let one
# placeholder run to the end of the document.
_PLACEHOLDER: Final = re.compile(r"\$\{([^}]{0,200})\}")


# Credential formats whose prefix is documented by the issuer. Only documented
# ones are listed: a prefix carried from memory would be a guess in a knowledge
# table (R-1.8, R-1.3). Sources:
# - GitHub token types:
#   https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github
# - AWS IAM unique ID prefixes:
#   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
CREDENTIAL_PREFIXES: Final = {
    "ghp_": "GitHub personal access token (classic)",
    "gho_": "GitHub OAuth access token",
    "ghu_": "GitHub App user access token",
    "ghs_": "GitHub App installation access token",
    "ghr_": "GitHub App refresh token",
    "github_pat_": "GitHub fine-grained personal access token",
    "AKIA": "AWS access key ID",
    "ASIA": "AWS temporary (STS) access key ID",
}

# A credential is often written with this in front of it, so the prefix test is
# applied to what follows as well as to the whole value.
_BEARER: Final = "Bearer "


@dataclass(frozen=True, slots=True)
class ValueShape:
    """What a config value is, never what it says.

    `form` is one of: `empty`, `reference` (the whole value is one placeholder),
    `mixed` (placeholders plus other text), `literal` (no placeholder at all).
    `length` is the raw value's length, which lets a report distinguish a short
    flag from something key-shaped without carrying either.

    `credential` names the documented format the value matches - `prefix:ghp_`,
    `jwt` - or is `None`. It is the only thing a detector gets to reason about,
    so a verdict about a secret is re-derivable from the label and the variable
    name without the report carrying the secret (R-7.2, R-7.3).
    """

    form: str
    references: tuple[str, ...]
    length: int
    credential: str | None = None


def _is_jwt(text: str) -> bool:
    """Three base64url segments whose first decodes to a JSON object with `alg`.

    Recognised by decoding rather than from a vendor table, so it needs no
    source of its own and cannot drift. The header is the discriminator: three
    dot-separated base64url runs also describe plenty of ordinary strings, while
    a first segment that decodes to `{"alg": ...}` is a JWS header by definition.
    """
    parts = text.split(".")
    if len(parts) != 3 or not all(parts[:2]):
        return False
    head = parts[0]
    try:
        raw = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
        decoded = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
    return isinstance(decoded, dict) and "alg" in decoded


def classify(text: str) -> str | None:
    """Label the credential format `text` matches, or `None`.

    Only the documented formats and the computable one are recognised. A key
    without a documented prefix is not labelled, which is a stated bound rather
    than an oversight: an entropy test would fire on commit hashes, UUIDs and
    base64 config blobs, and a check no real config can pass cleanly is the
    other half of R-2.4.
    """
    body = text[len(_BEARER) :] if text.startswith(_BEARER) else text
    for candidate in (text, body):
        for prefix in CREDENTIAL_PREFIXES:
            if candidate.startswith(prefix):
                return f"prefix:{prefix}"
    return "jwt" if _is_jwt(body) else None


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
        return ValueShape(form="literal", references=(), length=len(text), credential=classify(text))
    stripped = _PLACEHOLDER.sub("", text)
    form = "reference" if not stripped else "mixed"
    # A value that is entirely a placeholder holds no characters of its own, so
    # there is nothing to classify; a mixed one can still start with a prefix.
    credential = None if form == "reference" else classify(text)
    return ValueShape(form=form, references=found, length=len(text), credential=credential)


@dataclass(frozen=True, slots=True)
class EnvEntry:
    key: str
    shape: ValueShape
