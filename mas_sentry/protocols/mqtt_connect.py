# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared MQTT connection handling: distinct failure modes and CONNACK waiting.

Three probes in this package each open their own MQTT connection, and each
used to handle a failed one differently: the auth checker swallowed the error
and returned a partial mapping, the topic walker let a raw ConnectionRefusedError
escape, and the fingerprinter returned a dict carrying "broker_type":
"unreachable". A caller therefore could not tell "this broker is clean" from
"this probe never ran" without knowing which probe it had called.

Worse, none of them looked at the CONNACK reason code. A broker that answers
and rejects the CONNECT leaves the client connected at the socket level but
subscribed to nothing, so the walker returned an empty topic list - the same
value a genuinely idle broker returns. An enforced-authentication broker was
indistinguishable from an empty one.

This module gives all three the same two outcomes: unreachable at the transport
level, or reached and refused with the reason attached.

Note on reason codes: paho v2 hands the callback a ReasonCode object, not an
int. It compares equal to 0 on success and exposes the numeric code as
`.value`; calling int() on it raises TypeError. The helper here reads it the
way paho actually presents it.
"""

from __future__ import annotations

import time
from typing import Any

# A CONNACK that has not arrived within this window means the broker accepted
# the TCP connection and then went silent, which is a dead scan, not a slow one.
CONNACK_TIMEOUT_S = 5.0
_POLL_INTERVAL_S = 0.05


class BrokerUnreachable(ConnectionError):
    """The broker did not answer at the transport level.

    Distinct from an authentication rejection: unreachable must never be
    reported as "authentication enforced".
    """


class BrokerRefusedConnection(ConnectionError):
    """The broker answered and rejected the CONNECT.

    Carries the CONNACK reason so a caller can report why enumeration was not
    possible, instead of reporting an empty topic tree that reads as a clean
    result.
    """

    def __init__(self, reason: str, code: int) -> None:
        super().__init__(f"broker refused the connection: {reason} (code {code})")
        self.reason = reason
        self.code = code


def reason_text(rc: Any) -> str:
    """Human-readable CONNACK reason, whatever shape paho hands over."""
    return str(rc)


def reason_code(rc: Any) -> int:
    """Numeric CONNACK code. paho v2 exposes it as `.value`, not via int()."""
    value = getattr(rc, "value", rc)
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def await_connack(state: dict[str, Any], timeout: float = CONNACK_TIMEOUT_S) -> None:
    """Block until the on_connect callback records a reason code, then judge it.

    `state` is the dict an on_connect callback writes its reason code into under
    the key "rc". Raises BrokerUnreachable if no CONNACK arrives, or
    BrokerRefusedConnection if one arrives carrying a non-zero reason.
    """
    deadline = time.monotonic() + timeout
    while "rc" not in state and time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL_S)
    if "rc" not in state:
        raise BrokerUnreachable(f"no CONNACK within {timeout:.0f}s")
    rc = state["rc"]
    if rc != 0:
        raise BrokerRefusedConnection(reason_text(rc), reason_code(rc))
