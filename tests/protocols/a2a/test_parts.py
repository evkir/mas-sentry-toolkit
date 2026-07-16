# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for A2A artifact Part text extraction (v1.0 + v0.3.x shapes)."""

from __future__ import annotations

import base64

from mas_sentry.protocols.a2a.parts import (
    artifact_text,
    extract_part_text,
    iter_artifact_texts,
)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# --- text ---


def test_text_v1() -> None:
    assert extract_part_text({"text": "hello", "mediaType": "text/plain"}) == "hello"


def test_text_v03_with_kind() -> None:
    assert extract_part_text({"kind": "text", "text": "hello"}) == "hello"


# --- structured data ---


def test_data_serialised_sorted() -> None:
    assert extract_part_text({"data": {"b": 2, "a": 1}}) == '{"a": 1, "b": 2}'


def test_data_v03_with_kind() -> None:
    assert extract_part_text({"kind": "data", "data": {"k": "v"}}) == '{"k": "v"}'


def test_data_list() -> None:
    assert extract_part_text({"data": ["x", "y"]}) == '["x", "y"]'


# --- file: inline base64 (the false-negative case) ---


def test_raw_base64_decoded_v1() -> None:
    assert extract_part_text({"raw": _b64("secret CANARY"), "mediaType": "text/plain"}) == "secret CANARY"


def test_file_with_bytes_decoded_v03() -> None:
    assert extract_part_text({"kind": "file", "file": {"fileWithBytes": _b64("hidden")}}) == "hidden"


def test_file_bytes_key_decoded() -> None:
    # a2a python SDK spells the inline field `bytes`.
    assert extract_part_text({"file": {"bytes": _b64("payload")}}) == "payload"


def test_raw_invalid_base64_is_empty() -> None:
    assert extract_part_text({"raw": "!!!not-base64!!!"}) == ""


def test_raw_non_utf8_is_empty() -> None:
    non_utf8 = base64.b64encode(b"\xff\xfe\xfd").decode()
    assert extract_part_text({"raw": non_utf8}) == ""


# --- file: URI reference ---


def test_url_v1() -> None:
    assert extract_part_text({"url": "https://x.example/doc.pdf"}) == "https://x.example/doc.pdf"


def test_file_with_uri_v03() -> None:
    assert extract_part_text({"kind": "file", "file": {"fileWithUri": "https://y.example/a"}}) == "https://y.example/a"


def test_file_uri_key() -> None:
    assert extract_part_text({"file": {"uri": "https://z.example/b"}}) == "https://z.example/b"


# --- junk / precedence ---


def test_non_dict_part_is_empty() -> None:
    assert extract_part_text("not a part") == ""
    assert extract_part_text(None) == ""


def test_empty_part_is_empty() -> None:
    assert extract_part_text({}) == ""


def test_text_wins_over_data() -> None:
    assert extract_part_text({"text": "t", "data": {"x": 1}}) == "t"


# --- iteration over artifacts ---


def test_iter_artifact_texts_walks_parts() -> None:
    artifacts = [{"artifactId": "a1", "parts": [{"text": "one"}, {"data": {"k": "v"}}]}]
    assert list(iter_artifact_texts(artifacts)) == ["one", '{"k": "v"}']


def test_iter_skips_non_dict_and_missing_parts() -> None:
    artifacts = ["junk", {"no_parts": True}, {"parts": "not-a-list"}, {"parts": [{"text": "ok"}]}]
    assert list(iter_artifact_texts(artifacts)) == ["ok"]


def test_artifact_text_joins_and_drops_empty() -> None:
    artifacts = [{"parts": [{"text": "a"}, {}, {"raw": _b64("b")}]}]
    assert artifact_text(artifacts) == "a\nb"


def test_artifact_text_empty_when_no_text() -> None:
    assert artifact_text([{"parts": [{}]}]) == ""
    assert artifact_text([]) == ""
