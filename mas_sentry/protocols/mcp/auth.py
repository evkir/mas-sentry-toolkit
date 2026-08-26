# SPDX-License-Identifier: AGPL-3.0-or-later
"""What a refusal tells a client about how to authenticate.

An MCP server that requires OAuth answers an unauthenticated call with 401 and
a `WWW-Authenticate` header naming, per RFC 9728, the document that describes
its authorization servers. That header is the entry point to the whole
discovery chain, and the transport used to drop it: every response over 400 was
collapsed to its status code, so a scan against an authenticated server
reported "error 401" and threw away the address the server had just handed it.

Parsing here is deliberately narrow. The challenge is `auth-scheme` followed by
comma-separated `key="value"` parameters, and only the quoted form is read: the
SDK emits it and RFC 9728 uses it, while a token68 credential or an unquoted
parameter carries nothing this audit needs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# `key="value"`, tolerant of the whitespace real servers put around the equals.
_PARAM = re.compile(r'([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"')

# The challenge is written by the target. A header long enough to matter is a
# header meant to cost us something.
MAX_CHALLENGE_CHARS = 2000


@dataclass(frozen=True, slots=True)
class AuthChallenge:
    """One `WWW-Authenticate` challenge, as it arrived."""

    status: int
    scheme: str
    params: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    @property
    def resource_metadata(self) -> str:
        """The RFC 9728 document the server points at, or empty when it named none."""
        return self.params.get("resource_metadata", "")

    @property
    def detail(self) -> str:
        error = self.params.get("error", "")
        described = f" ({error})" if error else ""
        pointer = self.resource_metadata or "no resource_metadata parameter"
        return (
            f"The server refused an unauthenticated call with {self.status}{described} and pointed at "
            f"{pointer}. Probes ran without credentials, so nothing behind the authorization boundary "
            "was exercised."
        )


def parse_challenge(status: int, header: str) -> AuthChallenge | None:
    """Read a `WWW-Authenticate` header, or None when there is nothing to read."""
    text = (header or "").strip()[:MAX_CHALLENGE_CHARS]
    if not text:
        return None
    scheme = text.split(" ", 1)[0].strip()
    params = {key.lower(): value for key, value in _PARAM.findall(text)}
    return AuthChallenge(status=status, scheme=scheme, params=params, raw=text)
