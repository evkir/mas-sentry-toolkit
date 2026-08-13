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
_SUSPECT_PATTERNS = [
    re.compile(r"StdioServerParameters\([^)]*command\s*=\s*[^\"']*\b(user|request|body|param|argv)"),
    re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
    re.compile(r"os\.system\("),
    re.compile(r"exec\((?:rf|fr|f)['\"][^'\"]*\{"),  # f-string into exec
    re.compile(r"\.command\s*=\s*[^\"']*\b(input|json\[)", re.IGNORECASE),
]


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
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        self.scanned_files += 1
        for i, line in enumerate(text.splitlines(), start=1):
            for pat in _SUSPECT_PATTERNS:
                if pat.search(line):
                    self.findings.append(
                        StdioRceFinding(
                            file=str(f),
                            line=i,
                            snippet=line.strip()[:200],
                            pattern=pat.pattern,
                        )
                    )
                    break
