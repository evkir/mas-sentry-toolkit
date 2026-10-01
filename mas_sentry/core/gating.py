# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decide whether a scan's findings should fail the process that ran it.

The README promises a run is reproducible in CI. It was not actionable there:
every command returned 0 whatever it found, so a pipeline could record a scan
and not gate on one. `--fail-on` is that gate, and this module is the decision
behind it.

The gate reads severity names rather than `Finding` objects. Not every scan path
has been migrated to the unified model - the MCP scan, which carries the most
checks, still emits report rows as dicts whose `severity` is a plain `str` - and
a gate that only understood `Finding` would silently never fire for the command
with the largest detector surface.

Because those are plain strings, a value the gate cannot parse is reachable by a
module bug rather than by a config. Such a value counts as meeting the
threshold: a gate that ignores a row it does not understand lets through exactly
what it exists to catch. It is reported separately from the rows that genuinely
tripped it, so a red pipeline is never mysterious (R-2.1).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from .finding import Severity, rank

FINDINGS_EXIT_CODE: Final = 1
"""Exit status for a scan that ran and found something at or above the threshold.

Distinct from the 2 that every command already uses for a usage or scope error,
so a pipeline can tell "this scan found problems" from "this scan was invoked
wrongly" - the first is a result, the second is a broken job.
"""

THRESHOLD_NAMES: Final = tuple(s.value.lower() for s in Severity)


@dataclass(frozen=True, slots=True)
class GateResult:
    """Why a scan should or should not fail its caller.

    `triggered` holds the severities at or above the threshold. `unreadable`
    holds values that are not severities at all; both fail the gate, and keeping
    them apart is what lets the command say which happened.
    """

    triggered: tuple[str, ...]
    unreadable: tuple[str, ...]

    @property
    def failed(self) -> bool:
        return bool(self.triggered or self.unreadable)


def parse_severity(name: str) -> Severity:
    """Severity from a case-insensitive name.

    Raises `ValueError` naming the valid values, which is what a CLI turns into
    a usage error before a scan starts rather than after it: a threshold typo
    that surfaced at the end of a ten-minute scan would have wasted the scan.
    """
    try:
        return Severity(name.strip().upper())
    except ValueError:
        raise ValueError(f"unknown severity {name!r} (valid: {', '.join(THRESHOLD_NAMES)})") from None


def gate(severities: Iterable[str], threshold: Severity) -> GateResult:
    """Sort the observed severities into those that trip the threshold and those unreadable."""
    floor = rank(threshold)
    triggered: list[str] = []
    unreadable: list[str] = []
    for name in severities:
        try:
            severity = parse_severity(name)
        except ValueError:
            unreadable.append(name)
            continue
        if rank(severity) >= floor:
            triggered.append(severity.value)
    return GateResult(triggered=tuple(triggered), unreadable=tuple(unreadable))
