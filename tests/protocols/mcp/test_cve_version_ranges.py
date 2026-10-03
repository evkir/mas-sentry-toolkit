# SPDX-License-Identifier: AGPL-3.0-or-later
"""Version-range correlation, against a table written for the purpose.

The shipped table cannot exercise this. A survey of nine published servers on
2026-10-02 found seven that announce a version no range can be compared against,
and the three entries that survived the source review are all among them, so
every shipped entry takes the undecidable path. The ranges still have to work:
`firecrawl-mcp` and `@upstash/context7-mcp` both resolve their version from the
package at runtime, so an implementation that discloses its release is a case
this scanner will meet, and O-3/c4 widens the table toward the 2026 corpus.

These cases therefore substitute a table of their own and drive the CLI against
it (R-2.3). Each one states a release and what an operator should read in the
report, never how the comparison is implemented.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.protocols.mcp import cve_match, known_cves
from mas_sentry.protocols.mcp.known_cves import load_known_servers

from .test_cve_correlation import SERVER

runner = CliRunner()

# version_source = "server" is the case the shipped table has none of: an
# implementation that announces the release it actually is.
_TRUTHFUL = """
schema_version = 1

[[server]]
wire_name = "truthful-server"
distribution = "truthful-dist"
ecosystem = "pypi"
version_source = "server"

[[server.cve]]
id = "CVE-2026-11111"
fixed = "2.0.0"
severity = "HIGH"
summary = "a flaw fixed in 2.0.0"
source = "https://example.invalid/fixed"
verified = "2026-10-02"

[[server.cve]]
id = "CVE-2026-22222"
introduced = "1.5.0"
fixed = "1.9.0"
severity = "CRITICAL"
summary = "a flaw present only between 1.5.0 and 1.9.0"
source = "https://example.invalid/window"
verified = "2026-10-02"

[[server.cve]]
id = "CVE-2026-33333"
affected = "1.4.0"
severity = "CRITICAL"
summary = "a flaw the advisory pins to one release"
source = "https://example.invalid/named"
verified = "2026-10-02"
"""


_BOUNDED_ONLY = """
schema_version = 1

[[server]]
wire_name = "truthful-server"
distribution = "truthful-dist"
ecosystem = "pypi"
version_source = "server"

[[server.cve]]
id = "CVE-2026-11111"
fixed = "2.0.0"
severity = "HIGH"
summary = "a flaw fixed in 2.0.0"
source = "https://example.invalid/fixed"
verified = "2026-10-02"
"""


@pytest.fixture
def table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], None]]:
    """Swap in a table and drop the loader cache around the case."""

    def _write(text: str) -> None:
        path = tmp_path / "known_cves.toml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setattr(known_cves, "_TABLE", path)
        load_known_servers.cache_clear()

    yield _write
    load_known_servers.cache_clear()


@pytest.fixture
def server(tmp_path: Path) -> Path:
    path = tmp_path / "server.py"
    path.write_text(SERVER)
    return path


def _scan(server: Path, name: str, version: str, out: Path) -> list[dict[str, str]]:
    target = f"stdio://{sys.executable} {server} {name} {version}".rstrip()
    result = runner.invoke(app, ["mcp", "scan", "--target", target, "--checks", "fingerprint", "-o", str(out)])
    assert result.exit_code == 0, result.output
    rows: list[dict[str, str]] = json.loads(out.read_text(encoding="utf-8"))
    return rows


def _by_check(rows: list[dict[str, str]], check: str) -> list[dict[str, str]]:
    return [r for r in rows if r["check"] == check]


def test_a_release_below_the_fix_is_reported_with_both_sides_of_the_comparison(
    table, server: Path, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    """A reviewer has to be able to reach the verdict again from the row (R-7.2)."""
    table(_TRUTHFUL)
    rows = _scan(server, "truthful-server", "1.0.0", tmp_path / "out.json")

    hit = _by_check(rows, "known_cve")
    assert [r["severity"] for r in hit] == ["HIGH"], [r["detail"] for r in hit]
    assert "CVE-2026-11111" in hit[0]["detail"]
    assert "1.0.0" in hit[0]["detail"]
    assert "2.0.0" in hit[0]["detail"]
    assert "https://example.invalid/fixed" in hit[0]["detail"]


def test_a_patched_release_produces_no_cve_row_at_all(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The whole point of correlating by version: a patched target comes back clean.

    Every advisory here carries a fixed-in bound, which is what makes a wholly
    clean run possible: one that names a single version and no upper bound is
    undecidable above it by design, as the case below asserts.
    """
    table(_BOUNDED_ONLY)
    rows = _scan(server, "truthful-server", "2.0.0", tmp_path / "out.json")

    assert not _by_check(rows, "known_cve")
    assert not _by_check(rows, "known_cve_unverified")
    assert any(r["check"] == "fingerprint" for r in rows)


def test_a_release_below_the_introduction_is_not_given_the_flaw(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """An advisory with a window does not reach releases predating it."""
    table(_TRUTHFUL)
    rows = _scan(server, "truthful-server", "1.0.0", tmp_path / "out.json")

    assert "CVE-2026-22222" not in " ".join(r["detail"] for r in rows)


def test_a_release_inside_the_window_is_given_the_flaw_at_its_own_severity(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    table(_TRUTHFUL)
    rows = _scan(server, "truthful-server", "1.6.0", tmp_path / "out.json")

    hit = {r["severity"] for r in _by_check(rows, "known_cve") if "CVE-2026-22222" in r["detail"]}
    assert hit == {"CRITICAL"}


def test_a_release_the_advisory_names_is_a_hit(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    table(_TRUTHFUL)
    rows = _scan(server, "truthful-server", "1.4.0", tmp_path / "out.json")

    assert any("CVE-2026-33333" in r["detail"] for r in _by_check(rows, "known_cve"))


def test_a_release_outside_a_named_version_is_undecidable_rather_than_clean(
    table, server: Path, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    """No upper bound in the source means no basis for clearing a later release.

    2.5.0 is at or above the fix for the first advisory and past the window of
    the second, so both clear. The third names 1.4.0 and stops there, which is
    not the same as saying 2.5.0 is safe.
    """
    table(_TRUTHFUL)
    rows = _scan(server, "truthful-server", "2.5.0", tmp_path / "out.json")

    assert not _by_check(rows, "known_cve")
    unresolved = _by_check(rows, "known_cve_unverified")
    assert len(unresolved) == 1
    assert "CVE-2026-33333" in unresolved[0]["detail"]
    assert "no upper bound" in unresolved[0]["detail"]


def test_a_version_the_scanner_cannot_order_is_undecidable(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """A build string is not a release, and guessing an order would invent a verdict."""
    table(_TRUTHFUL)
    rows = _scan(server, "truthful-server", "nightly-main", tmp_path / "out.json")

    unresolved = _by_check(rows, "known_cve_unverified")
    assert len(unresolved) == 1
    assert "nightly-main" in unresolved[0]["detail"]
    assert not _by_check(rows, "known_cve")


def test_one_unresolved_row_carries_every_cve_that_shares_its_reason(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The reason is a property of the server, so it is stated once, not per CVE."""
    table(_TRUTHFUL.replace('version_source = "server"', 'version_source = "sdk"'))
    rows = _scan(server, "truthful-server", "1.0.0", tmp_path / "out.json")

    unresolved = _by_check(rows, "known_cve_unverified")
    assert len(unresolved) == 1
    for cve in ("CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333"):
        assert cve in unresolved[0]["detail"]
    assert "CRITICAL" in unresolved[0]["detail"]


def test_every_unusable_version_source_has_a_reason_to_report() -> None:
    """The two modules carry halves of one vocabulary and must not drift.

    known_cves.py decides which version_source values a table may use; cve_match
    holds the sentence each one puts in the report. A value added to the first
    without the second would raise KeyError mid-scan, on the undecidable path
    that most real targets take.
    """
    unusable = set(known_cves._VERSION_SOURCES) - {"server"}
    assert unusable == set(cve_match._UNUSABLE)
