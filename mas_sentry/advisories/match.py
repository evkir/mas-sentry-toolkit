# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decide whether an advisory applies to the release a lockfile pins.

Split from model.py on the line O-2 drew between known_cves.py and cve_match.py:
that module knows an advisory's shape, this one knows what a match means. It
reaches a verdict and explains it; turning a verdict into a report row is the
caller's job (R-1.7).

Three outcomes, not two, and the third is not an error path. An advisory can
carry a range this code cannot compare - a bound that is not a PEP 440 version,
or no affected versions at all - and a pinned release can be a direct URL or a
local path rather than a release number. Reporting either as "does not apply"
clears a release nobody checked, which is the silent loss R-2.1 ranks worst.
"""

from __future__ import annotations

from packaging.version import InvalidVersion, Version

from .model import Advisory, PinVerdict, VersionRange

# "0" is how OSV spells an interval with no lower bound. It parses as a version
# and compares below every real release, so the comparison below would be
# correct without this - but an advisory introduced at "0" is the common case,
# and saying so in the basis reads better than "1.2.3 is at or above 0".
_UNBOUNDED_BELOW = "0"


def verdict(advisory: Advisory, pinned: str) -> PinVerdict:
    """Weigh one pinned release against one advisory.

    `pinned` is the version a lockfile names, as written. Matching the package
    name is the source's job; by the time an advisory arrives here it is already
    known to be about the right distribution.
    """
    try:
        observed = Version(pinned)
    except InvalidVersion:
        return PinVerdict(
            advisory,
            None,
            f"{pinned!r} is not a PEP 440 version, so no range in {advisory.id} can be compared against it",
        )

    exact = _exact_match(advisory, observed)
    if exact is not None:
        return exact

    if not advisory.ranges:
        if not advisory.versions:
            return PinVerdict(
                advisory,
                None,
                f"{advisory.id} names no affected versions for {advisory.package}, so it bounds nothing",
            )
        listed = ", ".join(advisory.versions)
        return PinVerdict(advisory, False, f"{observed} is not among the versions {advisory.id} names ({listed})")

    for affected in advisory.ranges:
        try:
            hit = _in_range(observed, affected)
        except InvalidVersion as exc:
            return PinVerdict(
                advisory,
                None,
                f"{advisory.id} carries a bound this version scheme cannot read ({exc}), "
                f"so {observed} could not be placed against it",
            )
        if hit:
            return PinVerdict(advisory, True, _why_in(observed, affected))

    return PinVerdict(advisory, False, _why_out(observed, advisory))


def _exact_match(advisory: Advisory, observed: Version) -> PinVerdict | None:
    """Match against the explicit version list, which outranks the ranges.

    Compared as versions rather than as strings: a feed may list "1.0" where a
    lockfile pins "1.0.0", and those are the same release to PEP 440 and two
    different strings to everything else.

    An unreadable entry is skipped rather than fatal. The list is a set of
    independent claims, so one malformed entry says nothing about the others,
    and a range may still decide the verdict.
    """
    for candidate in advisory.versions:
        try:
            if Version(candidate) == observed:
                return PinVerdict(advisory, True, f"{observed} is named directly by {advisory.id}")
        except InvalidVersion:
            continue
    return None


def _in_range(observed: Version, affected: VersionRange) -> bool:
    """Whether `observed` falls inside one affected interval.

    Raises InvalidVersion when a bound cannot be read, which the caller turns
    into an unknown verdict: a range whose bound is unreadable decides nothing,
    and treating it as a miss would clear a release against a claim never tested.
    """
    if affected.introduced != _UNBOUNDED_BELOW and observed < Version(affected.introduced):
        return False
    if affected.fixed is not None:
        return observed < Version(affected.fixed)
    if affected.last_affected is not None:
        return observed <= Version(affected.last_affected)
    return True


def _why_in(observed: Version, affected: VersionRange) -> str:
    """State the bound the release fell inside, in the advisory's own terms."""
    start = "the first release" if affected.introduced == _UNBOUNDED_BELOW else affected.introduced
    if affected.fixed is not None:
        return f"{observed} is at or above {start} and below {affected.fixed}, the release that carries the fix"
    if affected.last_affected is not None:
        return f"{observed} is at or above {start} and at or below {affected.last_affected}, the last affected release"
    return f"{observed} is at or above {start} and the advisory names no fixed release"


def _why_out(observed: Version, advisory: Advisory) -> str:
    """State why no interval covered the release, naming the nearest fix.

    The fixed releases are listed rather than summarised: an operator reading
    "not affected" wants to see which bound cleared the pin, and a bare verdict
    sends them back to the advisory to find out.
    """
    fixes = [r.fixed for r in advisory.ranges if r.fixed is not None]
    if fixes:
        return f"{observed} is outside every affected range of {advisory.id} (fixed in {', '.join(fixes)})"
    return f"{observed} is outside every affected range of {advisory.id}"
