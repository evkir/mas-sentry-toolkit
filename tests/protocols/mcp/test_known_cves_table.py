# SPDX-License-Identifier: AGPL-3.0-or-later
"""The shipped CVE table, and the validation that keeps a broken one from scanning.

Two things are checked here. The first is that every entry in the table as
shipped carries what R-1.3 and R-2.13 require - a primary source and the date it
was read - because the defect this table replaces was an entry whose identifier
had no advisory behind it anywhere, and nothing in the old code could have said
so. The second is that the loader refuses a table it cannot read in full: a
missing key or an unparseable bound has to stop the run, since the alternative is
a scan correlating against fewer entries than the file lists and reporting the
result as a clean one (R-2.1).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mas_sentry.protocols.mcp import known_cves
from mas_sentry.protocols.mcp.known_cves import load_known_servers, server_for

_MINIMAL = """
schema_version = 1

[[server]]
wire_name = "demo"
distribution = "demo-dist"
ecosystem = "pypi"
version_source = "server"

[[server.cve]]
id = "CVE-2026-00000"
fixed = "1.2.3"
severity = "HIGH"
summary = "demo"
source = "https://example.invalid/advisory"
verified = "2026-10-02"
"""


@pytest.fixture
def table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    """Point the loader at a table under test and drop its cache around it."""

    def _write(text: str) -> Path:
        path = tmp_path / "known_cves.toml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setattr(known_cves, "_TABLE", path)
        load_known_servers.cache_clear()
        return path

    yield _write
    load_known_servers.cache_clear()


def test_every_shipped_entry_carries_a_primary_source_and_a_read_date() -> None:
    """The requirement the removed markitdown entry could not have met."""
    for server in load_known_servers().values():
        assert server.cves
        for cve in server.cves:
            assert cve.source.startswith("https://"), f"{cve.id} has no primary source"
            assert cve.verified.year >= 2025, f"{cve.id} has no plausible read date"


def test_a_shipped_entry_bounds_each_cve_exactly_one_way() -> None:
    """A range or a named version, never both and never neither."""
    for server in load_known_servers().values():
        for cve in server.cves:
            assert (cve.fixed is None) != (cve.affected is None), f"{cve.id} is bounded ambiguously"


def test_the_table_is_keyed_on_the_announced_name_not_the_distribution() -> None:
    """mcp-server-git announces mcp-git; keying on the distribution matches nothing."""
    assert server_for("mcp-git") is not None
    assert server_for("mcp-server-git") is None


def test_no_shipped_entry_claims_a_usable_version_it_does_not_disclose() -> None:
    """Every listed implementation was checked against its published package.

    None of the three announces a version a range comparison could use, which is
    the finding that shaped the schema rather than an accident of the data.
    """
    for server in load_known_servers().values():
        if server.version_is_usable:
            pytest.fail(f"{server.wire_name} claims version_source=server - re-verify against the package")


def test_a_lookup_is_exact_and_case_insensitive(table) -> None:  # type: ignore[no-untyped-def]
    table(_MINIMAL)
    assert server_for("DEMO") is not None
    assert server_for("demo-fork") is None
    assert server_for("  demo  ") is not None


@pytest.mark.parametrize(
    "key",
    ["severity", "source", "verified", "summary", "id"],
)
def test_an_entry_missing_a_required_field_stops_the_run(table, key: str) -> None:  # type: ignore[no-untyped-def]
    """Named in the error, so the operator looks at the right line of the file."""
    text = "\n".join(line for line in _MINIMAL.splitlines() if not line.startswith(f"{key} ="))
    table(text)
    with pytest.raises(ValueError, match=f"missing required key '{key}'"):
        load_known_servers()


@pytest.mark.parametrize(
    ("mangle", "message"),
    [
        ('severity = "HIGH"', 'severity = "URGENT"'),
        ('source = "https://example.invalid/advisory"', 'source = "see the blog post"'),
        ('verified = "2026-10-02"', 'verified = "last tuesday"'),
    ],
)
def test_an_entry_with_an_unusable_value_stops_the_run(table, mangle: str, message: str) -> None:  # type: ignore[no-untyped-def]
    """A value present but unusable is as bad as an absent one, and says which."""
    table(_MINIMAL.replace(mangle, message))
    with pytest.raises(ValueError):
        load_known_servers()


def test_an_unparseable_version_bound_stops_the_run(table) -> None:  # type: ignore[no-untyped-def]
    table(_MINIMAL.replace('fixed = "1.2.3"', 'fixed = "not-a-version"'))
    with pytest.raises(ValueError, match="unparseable"):
        load_known_servers()


def test_a_cve_bounded_both_ways_stops_the_run(table) -> None:  # type: ignore[no-untyped-def]
    table(_MINIMAL.replace('fixed = "1.2.3"', 'fixed = "1.2.3"\naffected = "1.0.0"'))
    with pytest.raises(ValueError, match="neither or both"):
        load_known_servers()


def test_an_unknown_version_source_stops_the_run(table) -> None:  # type: ignore[no-untyped-def]
    table(_MINIMAL.replace('version_source = "server"', 'version_source = "guesswork"'))
    with pytest.raises(ValueError, match="version_source"):
        load_known_servers()


def test_a_future_schema_version_stops_the_run(table) -> None:  # type: ignore[no-untyped-def]
    """A build must not read half of a table written for a later schema."""
    table(_MINIMAL.replace("schema_version = 1", "schema_version = 2"))
    with pytest.raises(ValueError, match="schema_version"):
        load_known_servers()


def test_a_duplicate_wire_name_stops_the_run(table) -> None:  # type: ignore[no-untyped-def]
    """Otherwise one entry silently shadows the other."""
    table(_MINIMAL + _MINIMAL.split("schema_version = 1", 1)[1])
    with pytest.raises(ValueError, match="twice"):
        load_known_servers()
