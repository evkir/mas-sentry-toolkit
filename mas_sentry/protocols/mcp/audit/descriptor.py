# SPDX-License-Identifier: AGPL-3.0-or-later
"""A tool descriptor: how it is recorded, and how it is shown as evidence.

Source: R-7.2, which says a finding carries both sides of what it claims, and
R-1.7, which says a module does one thing. Two detectors answer the same
question over different spans - `tool_drift` compares a scan against a baseline
committed next to a project, `tool_mutation` compares two enumerations inside
one scan - and a third, `authz_desync`, reads a baseline for the one name and
schema it may legitimately ask a server about. All three need the same two
things: a record of what a tool's descriptor was, and a way to put a descriptor
into a row so a reviewer rebuilds the verdict instead of trusting it.

Both lived in `tool_drift` until the second detector needed them, which made
one judge the supplier of another judge's evidence format. They are here
instead, and each detector is left deciding only what is worth reporting.

The baseline keeps the descriptor rather than a digest of it, and that is the
point of the format. A digest proves that something moved; it cannot say what
it moved from, so a row built on one can never carry both sides. It also
cannot say what a withdrawn tool's input schema was, which is the one input
that lets a probe ask a server about a tool it has stopped advertising without
guessing either the name or the arguments.

The file grew a container in 0.11.0. A baseline records what one scan saw,
and NS-8 is about more than tool descriptors: the negotiated protocol revision
and the prompt and resource inventories move between runs too, and a flat map
keyed by tool name has nowhere to put them. The document is therefore an
envelope with a version and a `tools` section, and the flat shapes below are
still read.

The version marker is what tells an envelope from a flat baseline, and it was
chosen by measuring the old reader rather than by argument. `_entry_from`
refuses any value that is neither a string nor an object, so no flat baseline
this product could write - or even read - can carry an integer, and branching
on one cannot collide with a document the flat reader accepts. A `tools` key
would not have been safe the same way: a server may advertise a tool called
`tools`, and a reader branching on that key would read its descriptor as the
tool map and report each of its fields as a withdrawn tool. An envelope handed
to 0.10.0 raises on the version key, which is the direction this has to fail
in (R-2.1): the older release refuses the file loudly instead of reporting a
clean tree it never compared.

Two flat shapes are therefore read as well. A string value is a digest written
by an earlier release: the change is still detected, and the row says the
prior side was never recorded instead of implying it was clean (R-2.1). An
object value carries the descriptor. Baselines are committed next to a project
and live in CI, so dropping either shape would silently stop detecting rug
pulls on every one of them.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..client import ToolDef


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """One tool as a baseline recorded it.

    The digest is always present, because it is what the comparison runs on in
    either shape. `description` is None only for the digest-only shape, which
    is how an entry reports that the prior side of a change is unavailable
    rather than empty.
    """

    digest: str
    description: str | None = None
    input_schema: dict[str, Any] | None = None

    @property
    def has_descriptor(self) -> bool:
        """Whether the prior side of a change can be read off this entry."""
        return self.description is not None


# The envelope's version, and the key that tells it from the two flat shapes. It
# is an integer because `_entry_from` refuses one, so the branch cannot misread
# any document the flat reader accepts. Bumped only when a reader of this
# release would misread a newer file: a section this release ignores does not
# need a bump, because ignoring one loses nothing a comparison depended on.
_BASELINE_VERSION = 2
_VERSION_KEY = "baseline_version"
_TOOLS_KEY = "tools"


@dataclass(frozen=True, slots=True)
class Baseline:
    """What one scan recorded, as the file keeps it.

    One section today. The container exists because the surfaces NS-8 names
    arrive next, and a flat map had nowhere to put them.
    """

    tools: dict[str, BaselineEntry] = field(default_factory=dict)


# A descriptor is bounded by nothing in the protocol: a server may answer with a
# megabyte of description, and every byte would travel into each of the four
# report formats. The cap is generous because the change a reviewer looks for is
# often deep inside a long description. The one case a cap can still hide is a
# difference past it, where both sides read alike, so a clipped field is named
# rather than left looking like no difference at all.
_MAX_EVIDENCE_CHARS = 1000


def _schema_text(schema: dict[str, Any] | None) -> str:
    return json.dumps(schema, sort_keys=True, separators=(",", ":"), default=str)


def _side(prefix: str, entry: BaselineEntry) -> dict[str, str]:
    """The descriptor as one side of a comparison had it."""
    return {
        f"{prefix}_description": entry.description or "",
        f"{prefix}_schema": _schema_text(entry.input_schema),
    }


def _clipped(values: dict[str, str]) -> dict[str, str]:
    """Cap every value and name the keys that hit the cap."""
    out = {key: text[:_MAX_EVIDENCE_CHARS] for key, text in values.items()}
    over = sorted(key for key, text in values.items() if len(text) > _MAX_EVIDENCE_CHARS)
    if over:
        out["truncated"] = ", ".join(over)
    return out


def change_evidence(prior: BaselineEntry, current: BaselineEntry) -> dict[str, str]:
    """What moved, and what it moved between.

    A digest-only baseline proves the change and can say nothing else. The
    honest shape is the current side with the gap named: inventing a prior side
    and dropping the row would each be a different lie (R-2.1).

    Each side carries the whole descriptor, not only the part that moved. The
    unchanged half is what lets a reviewer check `changed` instead of trusting
    it: with the schema omitted, "only the description moved" would be a claim
    the row asserts and nothing in it supports.
    """
    if not prior.has_descriptor:
        return {"baseline_format": "digest-only", **_clipped(_side("current", current))}
    moved = [
        name
        for name, changed in (
            ("description", prior.description != current.description),
            ("input_schema", prior.input_schema != current.input_schema),
        )
        if changed
    ]
    return {
        "changed": ", ".join(moved),
        **_clipped({**_side("previous", prior), **_side("current", current)}),
    }


def arrival_evidence(current: BaselineEntry) -> dict[str, str]:
    """A tool that was not there before. One side, and it is the current one."""
    return _clipped(_side("current", current))


def departure_evidence(prior: BaselineEntry) -> dict[str, str]:
    """A tool that was there and is no longer advertised.

    This is the one row whose prior side is the whole point: it carries the
    name and the input schema MST itself observed, which is what lets a later
    probe ask about the tool without guessing either.
    """
    if not prior.has_descriptor:
        return {"baseline_format": "digest-only"}
    return _clipped(_side("previous", prior))


def _digest(description: str, input_schema: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"description": description, "input_schema": input_schema},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()


def tool_descriptor_digest(tool: ToolDef) -> str:
    """Stable SHA-256 over a tool's security-relevant descriptor surface."""
    return _digest(tool.description, tool.input_schema)


def build_tool_baseline(tools: list[ToolDef]) -> dict[str, BaselineEntry]:
    """Record each tool's descriptor, keyed by name (last write wins on duplicates)."""
    return {
        t.name: BaselineEntry(
            digest=tool_descriptor_digest(t),
            description=t.description,
            input_schema=t.input_schema,
        )
        for t in tools
    }


def save_baseline(path: Path, baseline: Baseline) -> None:
    """Write the envelope, keeping the shape each tool entry actually has.

    An entry loaded from a digest-only file is written back as a digest.
    Filling in a descriptor it never carried would make the next run report a
    prior side that nothing ever observed.
    """
    payload: dict[str, Any] = {
        _VERSION_KEY: _BASELINE_VERSION,
        _TOOLS_KEY: {
            name: (
                {"description": entry.description, "input_schema": entry.input_schema}
                if entry.has_descriptor
                else entry.digest
            )
            for name, entry in baseline.tools.items()
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))


def _entry_from(name: str, value: Any) -> BaselineEntry:
    """One record, in whichever of the two flat shapes it was written."""
    if isinstance(value, str):
        return BaselineEntry(digest=value)
    if isinstance(value, dict):
        description = value.get("description")
        schema = value.get("input_schema")
        if isinstance(description, str) and isinstance(schema, dict):
            return BaselineEntry(
                digest=_digest(description, schema),
                description=description,
                input_schema=schema,
            )
    raise ValueError(f"baseline entry for '{name}' is neither a digest nor a descriptor")


def _tools_from(section: Any) -> dict[str, BaselineEntry]:
    """The tool map, from an envelope section or from a whole flat document."""
    if not isinstance(section, dict):
        raise ValueError(f"baseline '{_TOOLS_KEY}' section is not an object")
    return {str(name): _entry_from(str(name), value) for name, value in section.items()}


def load_baseline(path: Path) -> Baseline:
    """Load a baseline in any shape it was written in; empty if the file is absent.

    A record in no shape at all is refused rather than skipped. A baseline read
    in part would compare the live inventory against fewer tools than the file
    lists and report the remainder as unchanged.

    `type(version) is int` rather than `isinstance`, because `True` is an
    integer to `isinstance` and a hand-made file carrying one would be read as
    an envelope of version True.
    """
    if not path.exists():
        return Baseline()
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("baseline is not an object")
    version = data.get(_VERSION_KEY)
    if type(version) is not int:
        return Baseline(tools=_tools_from(data))
    if version > _BASELINE_VERSION:
        raise ValueError(f"baseline {_VERSION_KEY} {version} is newer than this release reads")
    return Baseline(tools=_tools_from(data.get(_TOOLS_KEY, {})))
