# SPDX-License-Identifier: AGPL-3.0-or-later
"""Heuristic agent identity inference for MAS where client_id is anonymous/random."""
from __future__ import annotations

import re

# Common conventions in MQTT-based MAS: `<scope>/<role>/<id>/<verb>`
_TOPIC_PREFIX_RE = re.compile(r"^(?P<scope>[^/]+)/(?P<role>[^/]+)/(?P<id>[^/]+)")


def infer_agent_id(client_id: str | None, topic: str) -> str:
    """
    Best-effort agent identity from (client_id, first observed topic).

    Strategy:
    1. If client_id is non-empty and not a random hex/UUID, use it verbatim.
    2. Otherwise derive from topic prefix conventions.
    3. Fall back to `inferred_<topic-root>`.
    """
    if client_id and not _looks_random(client_id):
        return client_id

    m = _TOPIC_PREFIX_RE.match(topic or "")
    if m:
        scope = m.group("scope").lower()
        role = m.group("role").lower()
        ident = m.group("id").lower()
        return f"{scope}_{role}_{ident}"

    root = (topic or "unknown").split("/")[0] or "unknown"
    return f"inferred_{root}"


def _looks_random(cid: str) -> bool:
    if len(cid) >= 16 and re.fullmatch(r"[a-fA-F0-9-]+", cid):
        return True
    if re.fullmatch(r"mqttjs_[a-z0-9]+", cid):
        return True
    return bool(re.fullmatch(r"auto-[a-zA-Z0-9]+", cid))
