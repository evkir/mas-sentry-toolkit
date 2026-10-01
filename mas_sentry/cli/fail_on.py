# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `--fail-on` option shared by every scanning command.

The decision lives in `core.gating`, which knows nothing about the CLI. This is
the part that belongs to the CLI: one help string so nine commands cannot drift
apart in what they promise, one callback so a bad threshold is a usage error
before the scan rather than after it, and one place that turns the result into an
exit status.
"""

from __future__ import annotations

from collections.abc import Iterable

import typer

from mas_sentry.core.console import make_console
from mas_sentry.core.gating import FINDINGS_EXIT_CODE, THRESHOLD_NAMES, gate, parse_severity

err_console = make_console(stderr=True)

FAIL_ON_HELP = (
    "Exit non-zero when a finding at or above this severity is reported: "
    f"{'|'.join(THRESHOLD_NAMES)}. Unset, the command always exits 0, which is "
    "what every release so far has done"
)


def validate_fail_on(value: str | None) -> str | None:
    """Typer callback: reject an unknown threshold before the scan runs."""
    if value is None:
        return None
    try:
        parse_severity(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    return value


def enforce_fail_on(severities: Iterable[str], fail_on: str | None) -> None:
    """Exit with `FINDINGS_EXIT_CODE` when the findings meet the threshold.

    A no-op when `--fail-on` was not passed, which keeps the exit status of every
    existing invocation unchanged: turning a scan that finds something into a
    non-zero exit by default would break every pipeline that runs one today
    without asking for a gate.
    """
    if fail_on is None:
        return
    result = gate(severities, parse_severity(fail_on))
    if not result.failed:
        return
    if result.triggered:
        counts: dict[str, int] = {}
        for name in result.triggered:
            counts[name] = counts.get(name, 0) + 1
        listed = ", ".join(f"{n} x{c}" for n, c in sorted(counts.items()))
        err_console.print(f"[fail-on {fail_on}] {listed}", markup=False, soft_wrap=True)
    if result.unreadable:
        # Reported rather than skipped: the gate failing on a value it could not
        # read is a module bug, and a red pipeline with no stated cause is worse
        # than the bug.
        err_console.print(
            f"[fail-on {fail_on}] unreadable severity value(s): {', '.join(repr(v) for v in result.unreadable)}",
            markup=False,
            soft_wrap=True,
        )
    raise typer.Exit(code=FINDINGS_EXIT_CODE)
