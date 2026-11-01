# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read the exact releases a requirements file pins, and say what it could not read.

An advisory lookup needs a distribution name and one released version. A
requirements file carries plenty that is neither - ranges, direct URLs, editable
checkouts, references to further files - and the useful product of reading one is
therefore two collections rather than one. Dropping the second is how a lockfile
audit comes back clean on a file it only half understood (R-2.1).

This parses rather than resolves. It never installs, never consults an index and
never follows a referenced file, so reading a hostile requirements file cannot do
anything but produce strings.

agentic.supply_chain reads the same files for a different question - whether a
spec is pinned and hashed at all - and keeps its own reader. The two are not
merged here because advisories must not depend on a detector, and because that
reader answers by counting while this one answers by name. If a third caller
appears, this module is the one to generalise: it is the only one that reports
what it failed to read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

# Hash fragments are stripped before parsing rather than after. PEP 508 has no
# room for them, so a file that keeps them on the requirement's own line - pip
# freeze output and hand-written lockfiles both do - makes every spec in it
# unparseable, and the audit then reports a fully pinned file as unreadable.
_INLINE_HASH = re.compile(r"\s--hash[=\s]\S+")

# Options that name another requirements file. They are called out rather than
# skipped: the pins in the file they name are not in this one, so an audit that
# ignored the line would report on part of a dependency set while sounding like
# it had read all of it.
_FILE_REFERENCE = ("-r", "--requirement", "-c", "--constraint")

# An editable install names a working tree, not a release.
_EDITABLE = ("-e", "--editable")


@dataclass(frozen=True, slots=True)
class Pin:
    """One distribution pinned to one exact version.

    `name` is the PEP 503 canonical form, because that is the only spelling an
    advisory feed can be keyed on: publishers write "Flask-Cors", lockfiles carry
    whatever pip wrote, and a lookup on the raw text misses most of them.

    `version` is kept as written rather than normalised. An arbitrary-equality
    pin (===) can name a string that is not a PEP 440 version at all, and
    normalising it here would either raise or quietly change what the file says;
    deciding whether it can be compared belongs to the matching rules.
    """

    name: str
    version: str
    raw: str


@dataclass(frozen=True, slots=True)
class Unpinned:
    """A requirement line that named no single released version, and why.

    Carried rather than dropped. Each of these is a package an advisory lookup
    cannot speak about, and an audit that omitted them would present a partial
    answer as a complete one.
    """

    raw: str
    reason: str


@dataclass(frozen=True, slots=True)
class PinSet:
    """Everything one requirements file said, split by whether it can be looked up."""

    pins: tuple[Pin, ...] = ()
    unpinned: tuple[Unpinned, ...] = ()

    def __len__(self) -> int:
        return len(self.pins) + len(self.unpinned)


def read_pins(path: Path) -> PinSet:
    """Read a requirements file from disk. See `parse_pins` for the rules."""
    return parse_pins(path.read_text(encoding="utf-8"))


def parse_pins(text: str) -> PinSet:
    """Split requirement lines into exact pins and everything else.

    Blank lines, comments and index options are structure rather than
    requirements and are passed over in silence. Every other line produces
    either a Pin or an Unpinned, so the two collections together account for the
    file.
    """
    pins: list[Pin] = []
    unpinned: list[Unpinned] = []
    for raw in _logical_lines(text):
        entry = _read_line(raw)
        if entry is None:
            continue
        if isinstance(entry, Pin):
            pins.append(entry)
        else:
            unpinned.append(entry)
    return PinSet(pins=tuple(pins), unpinned=tuple(unpinned))


def _logical_lines(text: str) -> list[str]:
    """Join backslash continuations, then drop blanks and comments.

    Continuations are joined rather than read line by line because a
    pip-compile lockfile writes the hashes of a requirement on the lines below
    it. Read separately those are not requirements and not structure either, and
    whichever way they were classified would be wrong.
    """
    joined = text.replace("\\\n", " ")
    out: list[str] = []
    for line in joined.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        without_comment = stripped.split(" #", 1)[0].strip()
        if without_comment:
            out.append(without_comment)
    return out


def _read_line(raw: str) -> Pin | Unpinned | None:
    """Classify one requirement line. None means the line is not a requirement."""
    first = raw.split()[0]
    if first in _EDITABLE or first.startswith(tuple(f"{e}=" for e in _EDITABLE)):
        return Unpinned(raw, "editable install, which names a working tree rather than a release")
    if first in _FILE_REFERENCE or first.startswith(tuple(f"{r}=" for r in _FILE_REFERENCE)):
        return Unpinned(raw, "reference to another requirements file, which this read did not follow")
    if raw.startswith("-"):
        return None
    if raw.startswith(("git+", "hg+", "svn+", "bzr+")):
        return Unpinned(raw, "version control checkout, which names a revision rather than a release")

    cleaned = _INLINE_HASH.sub("", raw).strip()
    try:
        requirement = Requirement(cleaned)
    except InvalidRequirement as exc:
        return Unpinned(raw, f"not a PEP 508 requirement ({exc})")

    if requirement.url:
        return Unpinned(raw, "installed from a direct URL, which names no released version")

    exact = [s.version for s in requirement.specifier if s.operator in ("==", "===")]
    if not exact:
        return Unpinned(raw, "no exact version pin, so there is no single release to check against")
    if len(set(exact)) > 1:
        return Unpinned(raw, f"names more than one exact version ({', '.join(sorted(set(exact)))})")

    version = exact[0]
    if not version.strip():
        # "pkg===" parses as a valid requirement carrying an empty version, so
        # this is reachable from a typo rather than from malformed input alone.
        # An empty string is not a release, and admitting it as a pin would put
        # a package into the checked set that no advisory can ever be weighed
        # against - counted as covered, never actually examined.
        return Unpinned(raw, "names an empty version, so it pins nothing")
    if version.endswith(".*"):
        return Unpinned(raw, f"pinned to the version range {version} rather than to one release")
    return Pin(name=canonicalize_name(requirement.name), version=version, raw=raw)
