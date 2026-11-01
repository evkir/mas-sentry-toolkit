# SPDX-License-Identifier: AGPL-3.0-or-later
"""The advisory pass over a lockfile, driven by a fake feed.

Every case here runs against an in-memory source. That is not a convenience:
the check must hold no socket, and a test that needed one would be the first
sign it had acquired one (R-7.3).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.advisories import Advisory, SourceState, VersionRange
from mas_sentry.agentic.supply_chain import SupplyChainContext, audit_supply_chain
from mas_sentry.cli import app

NOW = datetime(2026, 11, 1, tzinfo=UTC)

# PYSEC-2026-4320, the advisory the supply-chain workflow failed on in run #41.
# Carried as the fixture rather than an invented one so the pass is exercised
# against a record shaped the way a feed really writes them.
CERTIFI = Advisory(
    id="PYSEC-2026-4320",
    package="certifi",
    summary="certifi bundles the emSign ECC Root CA - G3 root; eMudhra intermediates are compromised.",
    references=("https://osv.dev/vulnerability/PYSEC-2026-4320",),
    ranges=(VersionRange(introduced="0", fixed="2026.10.19"),),
    aliases=("GHSA-6q48-6c7w-9gw2",),
)


class FakeSource:
    """A feed held in a dict, standing in for one the operator fetched."""

    def __init__(
        self,
        holdings: dict[str, tuple[Advisory, ...]] | None = None,
        *,
        available: bool = True,
        exported_at: datetime | None = NOW,
        reason: str = "fake feed",
    ) -> None:
        self._holdings = holdings or {}
        self._available = available
        self._exported_at = exported_at
        self._reason = reason

    def state(self) -> SourceState:
        return SourceState(
            available=self._available,
            reason=self._reason,
            exported_at=self._exported_at,
            record_count=len(self._holdings),
        )

    def advisories_for(self, package: str) -> tuple[Advisory, ...]:
        return self._holdings.get(package, ())


def _lockfile(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "requirements-lock.txt"
    path.write_text(body, encoding="utf-8")
    return path


def _titles(findings: list) -> list[str]:
    return [f.title for f in findings]


def _only(findings: list, needle: str) -> object:
    matches = [f for f in findings if needle in f.title]
    assert len(matches) == 1, f"expected one finding matching {needle!r}, got {_titles(findings)}"
    return matches[0]


class TestWithoutAFeed:
    def test_the_absence_of_a_feed_is_itself_a_finding(self, tmp_path: Path) -> None:
        """Skipping the check would produce the same empty result as a clean one (R-2.1)."""
        ctx = SupplyChainContext(requirements_path=_lockfile(tmp_path, "certifi==2026.5.20\n"), now=NOW)
        finding = _only(audit_supply_chain(ctx, "t"), "not checked against any advisory feed")
        assert finding.severity == "INFO"

    def test_it_says_a_clean_result_here_means_nothing(self, tmp_path: Path) -> None:
        ctx = SupplyChainContext(requirements_path=_lockfile(tmp_path, "certifi==2026.5.20\n"), now=NOW)
        finding = _only(audit_supply_chain(ctx, "t"), "not checked against any advisory feed")
        assert "does not mean the pins are clean" in finding.detail

    def test_it_sits_below_the_floor_the_self_audit_gates_on(self, tmp_path: Path) -> None:
        """INFO is deliberately under --fail-on low: an unconfigured feed must not redden CI."""
        from mas_sentry.core.gating import gate, parse_severity

        ctx = SupplyChainContext(requirements_path=_lockfile(tmp_path, "certifi==2026.5.20\n"), now=NOW)
        severities = [f.severity for f in audit_supply_chain(ctx, "t")]
        assert not gate(severities, parse_severity("low")).failed


class TestAHit:
    def _findings(self, tmp_path: Path, pinned: str) -> list:
        ctx = SupplyChainContext(
            requirements_path=_lockfile(tmp_path, f"certifi=={pinned}\n"),
            advisories=FakeSource({"certifi": (CERTIFI,)}),
            now=NOW,
        )
        return audit_supply_chain(ctx, "t")

    def test_an_affected_pin_is_reported(self, tmp_path: Path) -> None:
        assert _only(self._findings(tmp_path, "2026.5.20"), "PYSEC-2026-4320")

    def test_a_fixed_pin_is_not(self, tmp_path: Path) -> None:
        assert not [f for f in self._findings(tmp_path, "2026.10.23") if "PYSEC" in f.title]

    def test_the_advisory_url_rides_on_the_finding(self, tmp_path: Path) -> None:
        """Attribution by construction: CC-BY text travels into reports the operator publishes."""
        finding = _only(self._findings(tmp_path, "2026.5.20"), "PYSEC-2026-4320")
        assert finding.references == ("https://osv.dev/vulnerability/PYSEC-2026-4320",)

    def test_the_evidence_carries_the_comparison_that_was_made(self, tmp_path: Path) -> None:
        """A reviewer reaches the verdict again from the report without rerunning (R-7.2)."""
        finding = _only(self._findings(tmp_path, "2026.5.20"), "PYSEC-2026-4320")
        assert "2026.10.19" in finding.evidence["basis"]
        assert finding.evidence["pinned"] == "2026.5.20"

    def test_the_evidence_carries_the_age_of_the_data_behind_it(self, tmp_path: Path) -> None:
        finding = _only(self._findings(tmp_path, "2026.5.20"), "PYSEC-2026-4320")
        assert finding.evidence["advisory_db_age_days"] == 0
        assert finding.evidence["advisory_db_exported_at"] == NOW.isoformat()

    def test_aliases_are_kept_so_a_reader_can_match_another_id(self, tmp_path: Path) -> None:
        finding = _only(self._findings(tmp_path, "2026.5.20"), "PYSEC-2026-4320")
        assert "GHSA-6q48-6c7w-9gw2" in finding.evidence["aliases"]


class TestSeverity:
    def _finding(self, tmp_path: Path, stated: str | None) -> object:
        advisory = Advisory(
            id="GHSA-rated",
            package="pkg",
            summary="x",
            ranges=(VersionRange(introduced="0", fixed="2.0"),),
            severity=stated,
        )
        ctx = SupplyChainContext(
            requirements_path=_lockfile(tmp_path, "pkg==1.0\n"),
            advisories=FakeSource({"pkg": (advisory,)}),
            now=NOW,
        )
        return _only(audit_supply_chain(ctx, "t"), "GHSA-rated")

    @pytest.mark.parametrize("stated", ["CRITICAL", "HIGH", "LOW"])
    def test_a_stated_rating_is_used_as_given(self, tmp_path: Path, stated: str) -> None:
        assert self._finding(tmp_path, stated).severity == stated

    def test_an_unrated_advisory_falls_to_the_scanner_s_floor(self, tmp_path: Path) -> None:
        """PYSEC records often carry no rating; under-rating one would slip it under a gate."""
        assert self._finding(tmp_path, None).severity == "MEDIUM"

    def test_an_unrated_finding_says_whose_band_it_is(self, tmp_path: Path) -> None:
        """The band is the scanner's, and a reader must not take it for the advisory's."""
        assert "scanner's floor" in self._finding(tmp_path, None).detail

    def test_an_unreadable_rating_is_treated_as_no_rating(self, tmp_path: Path) -> None:
        """A band from a string nobody validated is a verdict the evidence does not support."""
        finding = self._finding(tmp_path, "catastrophic")
        assert finding.severity == "MEDIUM"
        assert finding.evidence["severity_stated_by_advisory"] is False


class TestWhatCouldNotBeChecked:
    def test_a_stale_feed_is_reported_and_its_findings_still_stand(self, tmp_path: Path) -> None:
        """Withholding real hits because the feed is old would lose data over a date."""
        ctx = SupplyChainContext(
            requirements_path=_lockfile(tmp_path, "certifi==2026.5.20\n"),
            advisories=FakeSource({"certifi": (CERTIFI,)}, exported_at=NOW - timedelta(days=30)),
            now=NOW,
        )
        findings = audit_supply_chain(ctx, "t")
        assert _only(findings, "30 days old").severity == "INFO"
        assert _only(findings, "PYSEC-2026-4320")

    def test_a_feed_inside_the_threshold_is_not_reported_as_old(self, tmp_path: Path) -> None:
        ctx = SupplyChainContext(
            requirements_path=_lockfile(tmp_path, "certifi==2026.10.23\n"),
            advisories=FakeSource({}, exported_at=NOW - timedelta(days=3)),
            now=NOW,
        )
        assert not [f for f in audit_supply_chain(ctx, "t") if "days old" in f.title]

    def test_lines_naming_no_release_are_reported_with_their_reasons(self, tmp_path: Path) -> None:
        """The referenced file is the case the existing pin counter cannot see at all."""
        ctx = SupplyChainContext(
            requirements_path=_lockfile(tmp_path, "-r base.txt\ncertifi==2026.10.23\n"),
            advisories=FakeSource({}),
            now=NOW,
        )
        finding = _only(audit_supply_chain(ctx, "t"), "name no release to check")
        assert finding.evidence["checked"] == 1
        assert "did not follow" in finding.evidence["unchecked"][0]["reason"]

    def test_an_advisory_that_cannot_be_compared_is_neither_hit_nor_clean(self, tmp_path: Path) -> None:
        unreadable = Advisory(
            id="GHSA-unreadable",
            package="pkg",
            summary="x",
            ranges=(VersionRange(introduced="0", fixed="latest"),),
        )
        ctx = SupplyChainContext(
            requirements_path=_lockfile(tmp_path, "pkg==1.0\n"),
            advisories=FakeSource({"pkg": (unreadable,)}),
            now=NOW,
        )
        findings = audit_supply_chain(ctx, "t")
        assert not [f for f in findings if "affected by" in f.title]
        pair = _only(findings, "could not be compared")
        assert "GHSA-unreadable" in pair.evidence["pairs"][0]


class TestThroughTheCli:
    """R-2.3: a unit test cannot notice that nobody calls the function."""

    def test_the_scan_reports_the_missing_feed_and_still_exits_zero(self, tmp_path: Path) -> None:
        lock = _lockfile(tmp_path, "certifi==2026.10.23\n")
        out = tmp_path / "out.json"
        result = CliRunner().invoke(
            app,
            [
                "agentic",
                "scan",
                "--target",
                "t",
                "--requirements",
                str(lock),
                "--asi",
                "supply_chain",
                "--fail-on",
                "low",
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        titles = [f["title"] for f in json.loads(out.read_text(encoding="utf-8"))]
        assert any("not checked against any advisory feed" in t for t in titles)

    def test_the_report_carries_a_references_list_findings_can_fill(self, tmp_path: Path) -> None:
        """Agentic findings reached reports with references always empty before this."""
        lock = _lockfile(tmp_path, "certifi==2026.10.23\n")
        out = tmp_path / "out.json"
        CliRunner().invoke(
            app,
            [
                "agentic",
                "scan",
                "--target",
                "t",
                "--requirements",
                str(lock),
                "--asi",
                "supply_chain",
                "--out",
                str(out),
            ],
        )
        assert "references" in json.loads(out.read_text(encoding="utf-8"))[0]
