# SPDX-License-Identifier: AGPL-3.0-or-later
"""The known-vulnerable server table, loaded from data rather than held in code.

The table used to be a dict literal inside fingerprint(), keyed on distribution
names and matched as a substring, which made three different mistakes
indistinguishable from each other: a key no server announces, an identifier with
no advisory behind it, and a product whose CVEs are not observable over MCP at
all. Keeping the knowledge in data with a mandatory source per entry (R-1.8,
R-1.3) makes each of those visible on review instead of on a scan.

The loader validates rather than trusts. A malformed table is a packaging or
editing accident, and the alternative to raising here is a scan that silently
correlates against fewer entries than the file lists - the silent-loss class this
project treats as its worst defect (R-2.1).

Version comparison is deliberately not done here. Whether a comparison is even
meaningful is a property of the server (see `version_source`), and acting on it
is the correlation step's job.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

_TABLE = Path(__file__).parent / "data" / "known_cves.toml"

_SCHEMA_VERSION = 1

_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})

# Whether the version a server announces can be compared against a CVE range.
# Only "server" can; the other three are the ways a real server fails to
# disclose its own release, each observed against a published package.
_VERSION_SOURCES = frozenset({"server", "sdk", "stale", "absent"})


@dataclass(frozen=True, slots=True)
class KnownCve:
    """One advisory against one implementation.

    `fixed` is exclusive and `affected` pins a single release; exactly one of the
    two is set, because an advisory either gives a bound or names a version, and
    turning the latter into a range would assert what it does not say.
    """

    id: str
    severity: str
    summary: str
    source: str
    verified: date
    fixed: str | None = None
    introduced: str | None = None
    affected: str | None = None


@dataclass(frozen=True, slots=True)
class KnownServer:
    """An implementation as a scan sees it: by the name it announces."""

    wire_name: str
    distribution: str
    ecosystem: str
    version_source: str
    cves: tuple[KnownCve, ...]

    @property
    def version_is_usable(self) -> bool:
        """Whether a range comparison against the announced version means anything."""
        return self.version_source == "server"


def _require(entry: dict[str, Any], key: str, where: str) -> Any:
    if key not in entry:
        raise ValueError(f"{_TABLE.name}: {where} is missing required key '{key}'")
    return entry[key]


def _parse_bound(value: Any, key: str, where: str) -> str | None:
    """Keep the bound as written, having proven it parses.

    Stored as the string from the file rather than as a Version so the report can
    quote the advisory verbatim; the parse here is what keeps an unreadable bound
    from reaching the comparison as a silent no-match.
    """
    if value is None:
        return None
    text = str(value)
    try:
        Version(text)
    except InvalidVersion as exc:
        raise ValueError(f"{_TABLE.name}: {where} has an unparseable {key} '{text}'") from exc
    return text


def _load_cve(entry: dict[str, Any], wire_name: str) -> KnownCve:
    where = f"{wire_name} cve"
    cve_id = str(_require(entry, "id", where))
    where = f"{wire_name} {cve_id}"

    severity = str(_require(entry, "severity", where))
    if severity not in _SEVERITIES:
        raise ValueError(f"{_TABLE.name}: {where} has severity '{severity}' outside {sorted(_SEVERITIES)}")

    source = str(_require(entry, "source", where))
    if not source.startswith("https://"):
        raise ValueError(f"{_TABLE.name}: {where} has no primary source URL")

    verified_raw = str(_require(entry, "verified", where))
    try:
        verified = date.fromisoformat(verified_raw)
    except ValueError as exc:
        raise ValueError(f"{_TABLE.name}: {where} has a verified date '{verified_raw}' that is not ISO-8601") from exc

    fixed = _parse_bound(entry.get("fixed"), "fixed", where)
    introduced = _parse_bound(entry.get("introduced"), "introduced", where)
    affected = _parse_bound(entry.get("affected"), "affected", where)
    if (fixed is None) == (affected is None):
        raise ValueError(f"{_TABLE.name}: {where} sets neither or both of 'fixed' and 'affected'")

    return KnownCve(
        id=cve_id,
        severity=severity,
        summary=str(_require(entry, "summary", where)),
        source=source,
        verified=verified,
        fixed=fixed,
        introduced=introduced,
        affected=affected,
    )


def _load_server(entry: dict[str, Any]) -> KnownServer:
    wire_name = str(_require(entry, "wire_name", "server entry")).lower()

    version_source = str(_require(entry, "version_source", wire_name))
    if version_source not in _VERSION_SOURCES:
        raise ValueError(
            f"{_TABLE.name}: {wire_name} has version_source '{version_source}' outside {sorted(_VERSION_SOURCES)}"
        )

    cves = tuple(_load_cve(c, wire_name) for c in _require(entry, "cve", wire_name))
    if not cves:
        raise ValueError(f"{_TABLE.name}: {wire_name} lists no CVE")

    return KnownServer(
        wire_name=wire_name,
        distribution=str(_require(entry, "distribution", wire_name)),
        ecosystem=str(_require(entry, "ecosystem", wire_name)),
        version_source=version_source,
        cves=cves,
    )


@lru_cache(maxsize=1)
def load_known_servers() -> dict[str, KnownServer]:
    """Parse and validate the table, keyed by the lowercased wire name.

    Cached because the file is shipped data that cannot change within a run, and
    a scan asks for it once per target.
    """
    raw = tomllib.loads(_TABLE.read_text(encoding="utf-8"))

    version = raw.get("schema_version")
    if version != _SCHEMA_VERSION:
        raise ValueError(f"{_TABLE.name}: schema_version is {version!r}, this build reads {_SCHEMA_VERSION}")

    servers: dict[str, KnownServer] = {}
    for entry in raw.get("server", []):
        server = _load_server(entry)
        if server.wire_name in servers:
            raise ValueError(f"{_TABLE.name}: '{server.wire_name}' appears twice")
        servers[server.wire_name] = server

    if not servers:
        raise ValueError(f"{_TABLE.name}: holds no server entries")
    return servers


def server_for(announced_name: str) -> KnownServer | None:
    """Look up by exact announced name, case-insensitively.

    Exact, not substring: the substring match this replaces gave every fork of a
    listed implementation the upstream CVEs, which is the one target whose
    maintainer had acted.
    """
    return load_known_servers().get(announced_name.strip().lower())
