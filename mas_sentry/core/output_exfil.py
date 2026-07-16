# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared agent-output exfiltration-channel scanner.

A neutral primitive, sibling to injection_scan: where that flags hidden
directives in content flowing *into* a model, this flags exfiltration channels
in content an agent emits. The 2026 disclosure class (EchoLeak CVE-2025-32711,
Salesforce ForcedLeak) turns agent output into a data-leak channel - the model
is induced to embed a Markdown image or link pointing at an external URL, and
the rendering client auto-fetches it, carrying any data folded into the URL out
of the trust boundary before a human sees anything.

Deterministic to detect, per the 2026 mitigation guidance: Markdown image
syntax, reference-style link definitions (used by EchoLeak to bypass link
redaction), and raw HTML img tags, each pointing at an http(s) URL. Data URIs
and relative paths are ignored - they trigger no external fetch.

Maps to CWE-201 (Insertion of Sensitive Information Into Sent Data) and OWASP
LLM05 (Improper Output Handling). No ATLAS technique is asserted - the clean
match is to the injection cause (AML.T0051), not the output-rendering effect.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# All three channels auto-fetch when the client renders the agent output.
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)")
_MARKDOWN_REF_LINK = re.compile(r"(?m)^[ \t]*\[[^\]]+\]:[ \t]*(https?://\S+)")
_HTML_IMAGE = re.compile(r"""(?i)<img\b[^>]*\bsrc\s*=\s*["']?(https?://[^\s"'>]+)""")

_CHANNELS = [
    ("markdown-image", _MARKDOWN_IMAGE),
    ("markdown-reference-link", _MARKDOWN_REF_LINK),
    ("html-image", _HTML_IMAGE),
]


@dataclass(frozen=True, slots=True)
class ExfilChannel:
    kind: str
    url: str


def scan_exfiltration_channels(text: str) -> list[ExfilChannel]:
    """Return external auto-fetch channels embedded in agent output text.

    Each match is a Markdown image, a reference-style link definition, or an HTML
    img pointing at an http(s) URL - a channel that leaks data on render. Results
    are de-duplicated by (kind, url) and sorted for stable output.
    """
    seen: set[tuple[str, str]] = set()
    out: list[ExfilChannel] = []
    for kind, pat in _CHANNELS:
        for m in pat.finditer(text):
            url = m.group(1)
            key = (kind, url)
            if key not in seen:
                seen.add(key)
                out.append(ExfilChannel(kind=kind, url=url))
    out.sort(key=lambda c: (c.kind, c.url))
    return out
