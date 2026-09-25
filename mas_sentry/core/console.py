# SPDX-License-Identifier: AGPL-3.0-or-later
"""The single Rich console factory for the whole toolkit.

``emoji=False`` is load-bearing, not cosmetic. Findings carry target-derived
evidence verbatim, and Rich's default console rewrites any ``:word:`` span into
an emoji before printing. The canonical proof of an LFI or SSRF is a line of
``/etc/passwd`` - ``root:x:0:0:root:/root:/bin/bash`` - whose ``:x:`` Rich
renders as a red cross, so the one string that proves the finding is the one
string the terminal corrupts. Disabling emoji substitution keeps evidence
byte-for-byte with what the probe observed.

``highlight=False`` stops Rich from recoloring numbers, paths and quoted spans
inside that same attacker-influenced text, which would otherwise dress hostile
output up in the console's own styling.
"""

from rich.console import Console


def make_console(*, stderr: bool = False) -> Console:
    """Return a Console configured to print target-derived text faithfully.

    ``stderr=True`` routes output to standard error, for the diagnostic
    consoles that must not pollute a report written to stdout.
    """
    return Console(emoji=False, highlight=False, stderr=stderr)
