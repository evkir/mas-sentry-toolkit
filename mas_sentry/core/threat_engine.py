# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unified Threat Engine — entry point for cross-module scans.

Independent of the legacy SentryEngine (core/engine.py). Modules are simple
callables that take a context dict and yield Finding objects. The engine
runs them in order, deduplicates results, and isolates failures so one
broken module does not abort the whole run.
"""

from __future__ import annotations

import hashlib
import json
import traceback
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from .finding import Finding, Severity, max_severity

ModuleFn = Callable[[dict[str, Any]], Iterable[Finding]]


@dataclass(slots=True)
class EngineRun:
    target: str
    modules_ran: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        return max_severity(self.findings)

    def by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]


@dataclass(slots=True)
class UnifiedThreatEngine:
    modules: dict[str, ModuleFn] = field(default_factory=dict)
    include_traceback: bool = False  # set True for verbose debug

    def register(self, name: str, fn: ModuleFn) -> None:
        self.modules[name] = fn

    def run(
        self,
        target: str,
        ctx: dict[str, Any],
        selected: list[str] | None = None,
    ) -> EngineRun:
        run = EngineRun(target=target)
        names = selected or list(self.modules.keys())
        seen: set[str] = set()
        for n in names:
            fn = self.modules.get(n)
            if not fn:
                run.errors.append({"module": n, "error": "not_registered"})
                continue
            run.modules_ran.append(n)
            try:
                for f in fn(ctx):
                    h = _hash_finding(f)
                    if h in seen:
                        continue
                    seen.add(h)
                    run.findings.append(f)
            except Exception as e:
                entry: dict[str, Any] = {"module": n, "error": str(e)}
                if self.include_traceback:
                    entry["traceback"] = traceback.format_exc()
                run.errors.append(entry)
        return run


def _hash_finding(f: Finding) -> str:
    """Stable hash over fields that define duplicate-equivalence.

    evidence may contain nested dicts/lists; json.dumps with sort_keys gives
    a canonical form. default=str is the safety net for non-JSON values
    (e.g. Path, datetime); they get stringified rather than raising.
    """
    payload = {
        "module": f.module,
        "title": f.title,
        "target": f.target,
        "evidence": f.evidence,
    }
    key = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha1(key.encode(), usedforsecurity=False).hexdigest()
