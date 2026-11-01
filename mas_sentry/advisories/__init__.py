# SPDX-License-Identifier: AGPL-3.0-or-later
"""Advisory lookup for pinned dependencies, kept off the scan's network path.

The package carries the vocabulary (model), the port a scan depends on (source)
and the matching rules (match). A feed loader lives behind the port and is the
only part that ever touches a file the operator fetched; the scan itself never
reaches the network, because R-7.3 says nothing about the target leaves the host
and a per-package advisory query would ship the target's dependency list.
"""

from .match import verdict
from .model import Advisory, PinVerdict, SourceState, VersionRange
from .source import AdvisorySource, NullSource

__all__ = [
    "Advisory",
    "AdvisorySource",
    "NullSource",
    "PinVerdict",
    "SourceState",
    "VersionRange",
    "verdict",
]
