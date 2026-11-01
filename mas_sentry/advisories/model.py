# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shapes an advisory lookup works in, independent of where advisories come from.

Modelled on the OSV schema (https://ossf.github.io/osv-schema/, read 2026-11-01)
because OSV is the only published advisory feed with a bulk export. That matters
for a product reason rather than a convenience one: a per-package query API would
send the target's dependency names and versions off the host, which R-7.3 forbids.
Downloading every PyPI advisory at once discloses nothing about what is scanned.

Nothing in this module touches the network, the filesystem or a clock. A source
implementation does all three, and this is the vocabulary it has to produce, so
the matching rules can be exercised with no feed present at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class VersionRange:
    """One interval of releases an advisory says is affected.

    OSV expresses an interval as an ordered event list; this is the resolved
    form of one such interval. `introduced` is inclusive and "0" means "from the
    first release", which is how OSV spells an advisory with no lower bound.

    The upper bound has three forms and they are not interchangeable. `fixed` is
    exclusive - the named release carries the fix and is out. `last_affected` is
    inclusive - the named release is the final vulnerable one, used where an
    advisory names no fix. Neither set means the interval is still open: nothing
    has shipped a fix, so every release from `introduced` up is affected. Folding
    the third case into either of the others would assert a bound the advisory
    does not state, which is the mistake known_cves.py avoids by keeping `fixed`
    and `affected` apart.
    """

    introduced: str = "0"
    fixed: str | None = None
    last_affected: str | None = None


@dataclass(frozen=True, slots=True)
class Advisory:
    """One advisory as it bears on one package.

    `package` is the PEP 503 canonical name. A feed spells names as the publisher
    typed them, so "Flask-Cors", "flask_cors" and "flask-cors" all reach us for
    the same distribution, and a lookup keyed on the raw spelling misses most of
    them - a silent miss, which R-2.1 ranks as this project's worst defect class.

    `references` carries the advisory's own source URLs and is not decoration.
    PyPI records in OSV come from GHSA (CC-BY-4.0) and PYSEC (CC0); CC-BY asks for
    attribution wherever the text travels, and a finding that quotes `summary`
    into a report the operator then publishes is where it travels. Carrying the
    URLs on the finding makes attribution structural rather than a step someone
    has to remember (R-1.3).

    `severity` is whatever the advisory states and None when it states nothing,
    which is common for PYSEC records. It is deliberately not defaulted here: a
    reporter inventing a severity the source never gave would be a verdict that
    no evidence supports (R-7.2), so the caller has to decide what an unrated
    advisory is worth and say so.
    """

    id: str
    package: str
    summary: str
    references: tuple[str, ...] = ()
    ranges: tuple[VersionRange, ...] = ()
    versions: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    severity: str | None = None
    modified: datetime | None = None


@dataclass(frozen=True, slots=True)
class SourceState:
    """Whether a source can answer at all, and how old its answers are.

    This exists so that "no advisory data" cannot be returned as an empty list of
    advisories. Those two readings - nothing is wrong, and nothing was checked -
    are the pair R-2.1 is about, and an empty list collapses them. A caller has to
    read `available` before it may treat a lack of advisories as a clean result.

    `reason` is filled in both states, not only the failing one: when a source is
    available it says how it was loaded, which is what a reviewer re-reads the
    verdict from (R-7.2).
    """

    available: bool
    reason: str
    exported_at: datetime | None = None
    record_count: int | None = None

    def age_days(self, now: datetime) -> int | None:
        """Whole days between the export timestamp and `now`, or None if unknown.

        `now` is passed in rather than read from a clock so a verdict about stale
        data is reproducible in a test and in CI (R-7.2).

        The age is measured from when the feed was exported, never from when the
        file was downloaded: those differ by however long the operator waited to
        run an update, and the download time flatters the data.

        A negative result is returned as it is rather than clamped to zero. It
        means the export timestamp is in the future, which is a clock problem or
        a tampered manifest - both worth reporting, and clamping hides them.
        """
        if self.exported_at is None:
            return None
        return (now - self.exported_at).days


@dataclass(frozen=True, slots=True)
class PinVerdict:
    """One advisory weighed against one pinned release.

    `applies` is None when the comparison could not be made at all, on the same
    three-outcome shape cve_match.CveVerdict uses. Neither True nor False is
    honest there: reporting "does not apply" would clear a release nobody
    checked, and reporting "applies" would condemn one.

    `basis` states the comparison in both directions so the verdict can be
    reached again from a report without rerunning the scan (R-7.2).
    """

    advisory: Advisory
    applies: bool | None
    basis: str
