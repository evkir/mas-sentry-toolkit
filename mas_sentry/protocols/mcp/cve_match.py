# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decide whether a listed CVE applies to the release a target announced.

Separate from known_cves.py on the same line O-2 drew between surface.py and
executable.py: that module knows the table's shape, this one knows what a match
means. It reaches a verdict and explains it; turning a verdict into a report row
belongs to the caller.

Three outcomes, not two. A survey of nine published servers on 2026-10-02 found
that seven announce a version no range can be compared against - the official
mcp-server-git, mcp-server-time and mcp-server-fetch all report the version of
the SDK, and the official filesystem and memory servers report literals frozen
at 0.2.0 and 0.6.3 against a 2026.8.31 release - so "cannot tell" is the common
case here rather than the error path. Reporting it as a clean result would hide
a vulnerable target, and reporting it as a hit would condemn a patched one; both
are the silent-loss class this project treats as its worst defect (R-2.1).

Every verdict carries the comparison it rests on, in both directions, so a
reviewer can reach it again from the report without rerunning the scan (R-7.2).
"""

from __future__ import annotations

from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

from .known_cves import KnownCve, KnownServer

# Why the announced version cannot carry a comparison. Phrased as what the
# server did, because the operator's next step differs for each: a stale literal
# can be resolved by reading the deployed package, an SDK version cannot.
_UNUSABLE = {
    "sdk": "announces the version of the SDK it is built on rather than its own release",
    "stale": "announces a hardcoded version that stopped following its releases",
    "absent": "announces no version at all",
}


@dataclass(frozen=True, slots=True)
class CveVerdict:
    """One advisory weighed against one observed release.

    `applies` is None when the comparison could not be made. That is not a
    failure of the scan but a property of what the server disclosed, and it is
    reported as its own outcome rather than folded into either answer.
    """

    cve: KnownCve
    applies: bool | None
    basis: str


def _bounded_verdict(cve: KnownCve, observed: Version, announced: str) -> CveVerdict:
    """Weigh a release against an advisory that gives a fixed-in bound."""
    assert cve.fixed is not None
    if cve.introduced is not None and observed < Version(cve.introduced):
        return CveVerdict(
            cve,
            False,
            f"{announced} is below {cve.introduced}, where the advisory says the flaw was introduced",
        )
    if observed < Version(cve.fixed):
        return CveVerdict(cve, True, f"{announced} is below {cve.fixed}, the release that carries the fix")
    return CveVerdict(cve, False, f"{announced} is at or above {cve.fixed}, the release that carries the fix")


def _named_verdict(cve: KnownCve, observed: Version, announced: str) -> CveVerdict:
    """Weigh a release against an advisory that names one version and no bound.

    A mismatch is undecidable rather than clean. The advisory named the version
    it was tested against and said nothing about an upper bound, so a later
    release may or may not carry a fix, and calling it clean would assert what
    no source does.
    """
    assert cve.affected is not None
    if observed == Version(cve.affected):
        return CveVerdict(cve, True, f"{announced} is the release the advisory names")
    return CveVerdict(
        cve,
        None,
        f"the advisory names only {cve.affected} and gives no upper bound, so {announced} cannot be ruled in or out",
    )


def verdicts_for(server: KnownServer, announced_version: str) -> list[CveVerdict]:
    """Weigh every advisory listed against this implementation.

    The version is judged once, not per CVE: whether a server discloses its own
    release is a property of the server, so an unusable version makes every
    listed advisory undecidable for the same stated reason.
    """
    if not server.version_is_usable:
        reason = _UNUSABLE[server.version_source]
        shown = announced_version or "nothing"
        basis = f"the server {reason} (observed: {shown})"
        return [CveVerdict(cve, None, basis) for cve in server.cves]

    announced = announced_version.strip()
    try:
        observed = Version(announced)
    except InvalidVersion:
        basis = f"the announced version {announced!r} is not a version this scanner can order"
        return [CveVerdict(cve, None, basis) for cve in server.cves]

    return [
        _bounded_verdict(cve, observed, announced)
        if cve.fixed is not None
        else _named_verdict(cve, observed, announced)
        for cve in server.cves
    ]
