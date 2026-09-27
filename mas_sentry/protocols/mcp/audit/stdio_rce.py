# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detect the OX Security MCP STDIO RCE class.

Reference: 'The Mother of All AI Supply Chains' (OX Security, 2026).
The flaw: user-controlled values reach `StdioServerParameters.command` which
is then executed without shell-safety. Affects Python/TS/Java/Rust official SDKs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Patterns that indicate user-input flowing into command construction.
#
# The spans are capped rather than open-ended. A match runs over the whole
# file, so an unbalanced parenthesis would otherwise let one call's opening
# pair with a keyword hundreds of lines further down. The cap is applied
# while matching, not to a string that was already built.
_MAX_ARG_SPAN = 400
_MAX_VALUE_SPAN = 120

_SUSPECT_PATTERNS = [
    re.compile(
        rf"StdioServerParameters\([^)]{{0,{_MAX_ARG_SPAN}}}command\s*=\s*"
        rf"[^\"']{{0,{_MAX_VALUE_SPAN}}}\b(user|request|body|param|argv)"
    ),
    re.compile(rf"subprocess\.\w+\([^)]{{0,{_MAX_ARG_SPAN}}}shell\s*=\s*True"),
    re.compile(r"os\.system\("),
    re.compile(r"exec\((?:rf|fr|f)['\"][^'\"]*\{"),  # f-string into exec
    re.compile(rf"\.command\s*=\s*[^\"']{{0,{_MAX_VALUE_SPAN}}}\b(input|json\[)", re.IGNORECASE),
]

# How much source a snippet may quote, bounded before the slice is taken so a
# minified one-line bundle cannot build a multi-megabyte intermediate string.
_MAX_SNIPPET_SOURCE = 400
_MAX_SNIPPET_CHARS = 200


@dataclass(frozen=True, slots=True)
class StdioRceFinding:
    file: str
    line: int
    snippet: str
    pattern: str


@dataclass(slots=True)
class StdioConfigAuditor:
    findings: list[StdioRceFinding] = field(default_factory=list)
    # Counted so a caller can tell "the tree is clean" from "the path matched
    # no source at all". Both produce an empty finding list, and only one of
    # them is evidence of anything.
    scanned_files: int = 0

    def scan_path(self, path: str | Path) -> list[StdioRceFinding]:
        p = Path(path)
        if p.is_file():
            self._scan_file(p)
        else:
            for ext in ("*.py", "*.ts", "*.js"):
                for f in p.rglob(ext):
                    self._scan_file(f)
        return self.findings

    def _scan_file(self, f: Path) -> None:
        """Match against the whole file, not a line at a time.

        The construct this detector is named for is written across lines by
        every formatter - StdioServerParameters( on one, command= on the
        next - so a line-at-a-time scan saw the call opening and its
        dangerous argument as two unrelated pieces of text and reported the
        file clean. The patterns already tolerate newlines; only the unit of
        matching was wrong.

        One finding per starting line, which is what breaking out of the
        pattern loop used to give, so a site is not reported once per pattern
        that happens to cover it.
        """
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        by_line: dict[int, StdioRceFinding] = {}
        for pat in _SUSPECT_PATTERNS:
            for m in pat.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                if line in by_line:
                    continue
                by_line[line] = StdioRceFinding(
                    file=str(f),
                    line=line,
                    snippet=_snippet(text, m.start(), m.end()),
                    pattern=pat.pattern,
                )
        self.findings.extend(by_line[k] for k in sorted(by_line))


def _snippet(text: str, start: int, end: int) -> str:
    """Quote whole lines from the start of the match to the end of its last.

    A match can stop mid-line (``os.system(``), and the argument that makes
    it a finding sits after it, so quoting the match alone drops the evidence.
    """
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line_end = min(line_end, line_start + _MAX_SNIPPET_SOURCE)
    return " ".join(text[line_start:line_end].split())[:_MAX_SNIPPET_CHARS]
