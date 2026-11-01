# SPDX-License-Identifier: AGPL-3.0-or-later
"""Where advisories come from, as a port the scan depends on rather than a client.

The scan must not reach the network. R-7.3 says nothing about the target leaves
the host, and a dependency audit is the one check where breaking that would be
easy to miss: querying an advisory API package by package ships the target's
whole dependency list to a third party, one request at a time.

Keeping the lookup behind a port is what makes that boundary reviewable. A
source loads a feed the operator fetched deliberately, by its own command, and
the scan only ever asks a loaded source questions. A source that opened a socket
when asked for advisories would be visible as a violation here rather than
buried in a detector.

The port is deliberately two methods rather than one. `state` answers whether
the source can speak at all; `advisories_for` answers what it has on a package.
Merging them into a single call that returns a list leaves "no feed installed"
and "this package has no advisories" spelled the same way, and the caller that
cannot tell them apart reports an unchecked scan as a clean one (R-2.1).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .model import Advisory, SourceState


@runtime_checkable
class AdvisorySource(Protocol):
    """A loaded body of advisories that can be asked about one package at a time."""

    def state(self) -> SourceState:
        """Whether this source can answer, and how old its data is.

        Callers read this before trusting an empty result from `advisories_for`.
        """
        ...

    def advisories_for(self, package: str) -> tuple[Advisory, ...]:
        """Every advisory this source holds for `package`, by any name spelling.

        The package name is normalised by the implementation, not by the caller:
        a caller that forgot would get an empty tuple that reads as "clean".
        Returns an empty tuple when the source is loaded and the package is
        genuinely unaffected - which is only a clean result if `state` says the
        source is available.
        """
        ...


class NullSource:
    """A source that holds nothing, used where no feed has been configured.

    The default has to be a source rather than None. A detector written against
    an optional source grows a branch that skips the check, and a skipped check
    produces no findings - indistinguishable, in the report, from a check that
    ran and found nothing. Answering "unavailable" to every question keeps the
    unchecked state in the data where a report can carry it.
    """

    _REASON = "no advisory database configured; run 'mas-sentry advisories update' or pass --advisory-db"

    def state(self) -> SourceState:
        return SourceState(available=False, reason=self._REASON)

    def advisories_for(self, package: str) -> tuple[Advisory, ...]:
        return ()
