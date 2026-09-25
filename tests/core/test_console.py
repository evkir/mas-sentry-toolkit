# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shared console must print target-derived evidence byte-for-byte.

Regression guard: a finding proving LFI/SSRF quotes a line of /etc/passwd, and
Rich's default console rewrites the ``:x:`` in ``root:x:0:0`` into an emoji -
corrupting the one string that proves the finding. The factory disables emoji
substitution and number highlighting for exactly this reason.
"""

from mas_sentry.core.console import make_console

PASSWD_LINE = "root:x:0:0:root:/root:/bin/bash"


def test_emoji_shortcodes_in_evidence_are_not_substituted() -> None:
    console = make_console()
    with console.capture() as cap:
        console.print(PASSWD_LINE)
    out = cap.get()
    assert ":x:" in out
    assert "❌" not in out  # ❌, the cross-mark :x: would expand to


def test_other_colon_shortcodes_survive_too() -> None:
    """Not just :x: - any :word: span in a payload must pass through intact."""
    console = make_console()
    payload = "status=:warning: pending :heavy_check_mark:"
    with console.capture() as cap:
        console.print(payload)
    assert cap.get().strip() == payload


def test_passthrough_kwargs_reach_the_console() -> None:
    console = make_console(stderr=True)
    assert console.stderr is True
