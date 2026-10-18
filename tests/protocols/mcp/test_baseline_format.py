# SPDX-License-Identifier: AGPL-3.0-or-later
"""The baseline file format: one envelope, two flat shapes it replaced.

Source: `audit/descriptor.py`, and NS-8. The envelope exists so a baseline can
record more than tool descriptors. Everything below is about the one property
that matters when a format changes under files living in other people's CI: a
baseline is read whole or refused, never in part (R-2.1).

The discriminator is measured, not argued. `_entry_from` refuses any value that
is neither a string nor an object, so an integer cannot appear in a flat
baseline this product wrote or would accept, and a version key carrying one
cannot be mistaken for a tool. The test for the tool named `tools` is the
negative half of that: it is the collision a `tools`-sniffing reader would have
had, and it has to stay absent.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mas_sentry.protocols.mcp.audit.descriptor import (
    Baseline,
    build_tool_baseline,
    load_baseline,
    save_baseline,
    tool_descriptor_digest,
)
from mas_sentry.protocols.mcp.client import ToolDef

_DESCRIPTOR = {"description": "transfers funds", "input_schema": {"type": "object"}}


def _write(path: Path, doc: Any) -> Path:
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_what_is_written_is_an_envelope(tmp_path: Path) -> None:
    """The shape on disk, asserted on the file rather than through the reader.

    Round-tripping through this module's own reader would pass for a writer
    that invented any shape at all, so the document is read as JSON here.
    """
    path = tmp_path / "b.json"
    tools = [ToolDef(name="pay", description="transfers funds", input_schema={"type": "object"})]
    save_baseline(path, Baseline(tools=build_tool_baseline(tools)))
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["baseline_version"] == 2, "the version is what tells a reader which shape this is"
    assert sorted(doc) == ["baseline_version", "tools"], "no tool name sits at the top level any more"
    assert doc["tools"]["pay"]["description"] == "transfers funds"


def test_an_envelope_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "b.json"
    baseline = Baseline(tools=build_tool_baseline([ToolDef(name="pay", description="d")]))
    save_baseline(path, baseline)
    assert load_baseline(path) == baseline


def test_a_flat_descriptor_baseline_is_still_read(tmp_path: Path) -> None:
    """The shape 0.10.0 wrote. Dropping it would stop drift detection in place."""
    entry = load_baseline(_write(tmp_path / "flat.json", {"pay": _DESCRIPTOR})).tools["pay"]
    assert entry.description == "transfers funds"
    assert entry.has_descriptor is True


def test_a_flat_digest_baseline_is_still_read(tmp_path: Path) -> None:
    """The oldest shape: it proves a change and admits it can say nothing else."""
    before = ToolDef(name="pay", description="transfers funds", input_schema={"type": "object"})
    path = _write(tmp_path / "v1.json", {"pay": tool_descriptor_digest(before)})
    entry = load_baseline(path).tools["pay"]
    assert entry.digest == tool_descriptor_digest(before)
    assert entry.has_descriptor is False


def test_a_digest_only_entry_is_written_back_as_a_digest(tmp_path: Path) -> None:
    """Re-saving a loaded old baseline must not invent a prior side for it."""
    before = ToolDef(name="pay", description="transfers funds", input_schema={"type": "object"})
    loaded = load_baseline(_write(tmp_path / "v1.json", {"pay": tool_descriptor_digest(before)}))
    out = tmp_path / "again.json"
    save_baseline(out, loaded)
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["tools"]["pay"] == tool_descriptor_digest(before), "a digest stays a digest"


def test_a_flat_baseline_may_hold_a_tool_called_tools(tmp_path: Path) -> None:
    """The collision a `tools`-sniffing reader would have had, and must not.

    `tools` is a legal tool name. Read as an envelope, this document would hand
    the reader one descriptor as the tool map and report `description` and
    `input_schema` as two tools that have since been withdrawn.
    """
    path = _write(tmp_path / "flat.json", {"tools": _DESCRIPTOR, "pay": _DESCRIPTOR})
    assert sorted(load_baseline(path).tools) == ["pay", "tools"]


def test_a_missing_file_is_an_empty_baseline(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "absent.json") == Baseline()


def test_a_newer_envelope_is_refused_rather_than_read_in_part(tmp_path: Path) -> None:
    """A file from a later release is refused: reading the sections this one
    happens to know would compare against part of what the file records."""
    path = _write(tmp_path / "future.json", {"baseline_version": 99, "tools": {"pay": _DESCRIPTOR}})
    with pytest.raises(ValueError, match="newer than this release"):
        load_baseline(path)


def test_an_envelope_whose_tools_section_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "bad.json", {"baseline_version": 2, "tools": ["pay"]})
    with pytest.raises(ValueError, match="is not an object"):
        load_baseline(path)


def test_an_unreadable_entry_is_refused_rather_than_skipped(tmp_path: Path) -> None:
    """One bad record fails the load. Skipping it would report every remaining
    tool as unchanged against a baseline that was never fully read."""
    path = _write(tmp_path / "bad.json", {"baseline_version": 2, "tools": {"pay": _DESCRIPTOR, "odd": 7}})
    with pytest.raises(ValueError, match="neither a digest nor a descriptor"):
        load_baseline(path)


def test_a_document_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path / "list.json", ["pay"])
    with pytest.raises(ValueError, match="not an object"):
        load_baseline(path)
