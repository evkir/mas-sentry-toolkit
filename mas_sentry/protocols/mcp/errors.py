# SPDX-License-Identifier: AGPL-3.0-or-later
"""Failures that end a scan before any check could run.

A target that refuses the connection, a command that is not on the path, a
process that exits during the handshake: none of these is a finding about the
server's security posture, and none of them is a bug in this scanner. They are
the scan not happening, which is a fact the report has to carry.

Raised rather than returned because there is nothing to return - no inventory,
no capabilities, no route. The runtime catches them at the top and writes the
gap, so `mcp scan` and `a2a scan` behave the way `mqtt scan` and `amqp scan`
already do: a file is written, the reason is in it, and a pipeline that pipes a
scan into `report convert` keeps working instead of breaking on a missing file
and a traceback.
"""

from __future__ import annotations


class TargetUnreachable(RuntimeError):
    """The target could not be reached at all.

    A RuntimeError so that callers written before these types existed - and the
    cases pinning them - keep catching what they always caught. The runtime
    catches this class by name, not by base, so an unrelated RuntimeError still
    travels as the defect it is.
    """


class HandshakeFailed(TargetUnreachable):
    """The target answered, but never completed the MCP handshake.

    A subclass rather than a separate type: to a report both mean the same
    thing - no check ran - and the difference between them is already carried
    by the message.
    """
