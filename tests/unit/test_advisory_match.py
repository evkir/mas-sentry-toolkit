# SPDX-License-Identifier: AGPL-3.0-or-later
"""What a verdict means, exercised with no feed present.

The cases that matter most here are the ones returning None. A three-outcome
verdict is only worth its complexity if the third outcome is reachable, so each
way of reaching it gets a test: an unreadable pin, an unreadable bound, and an
advisory that bounds nothing. Without these the type would say "unknown" while
the code could only ever answer yes or no.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mas_sentry.advisories import Advisory, NullSource, SourceState, VersionRange, verdict


def _advisory(**kwargs: object) -> Advisory:
    base: dict[str, object] = {
        "id": "GHSA-test-0001",
        "package": "certifi",
        "summary": "test advisory",
        "references": ("https://example.invalid/GHSA-test-0001",),
    }
    base.update(kwargs)
    return Advisory(**base)  # type: ignore[arg-type]


class TestRangeBounds:
    def test_a_release_below_the_introduced_bound_is_not_affected(self) -> None:
        adv = _advisory(ranges=(VersionRange(introduced="2.0", fixed="3.0"),))
        assert verdict(adv, "1.9").applies is False

    def test_a_release_inside_the_interval_is_affected(self) -> None:
        adv = _advisory(ranges=(VersionRange(introduced="2.0", fixed="3.0"),))
        assert verdict(adv, "2.5").applies is True

    def test_the_fixed_release_itself_is_not_affected(self) -> None:
        """`fixed` is exclusive: the named release is the one carrying the fix."""
        adv = _advisory(ranges=(VersionRange(introduced="2.0", fixed="3.0"),))
        assert verdict(adv, "3.0").applies is False

    def test_the_last_affected_release_itself_is_affected(self) -> None:
        """`last_affected` is inclusive, which is what separates it from `fixed`."""
        adv = _advisory(ranges=(VersionRange(introduced="2.0", last_affected="3.0"),))
        assert verdict(adv, "3.0").applies is True

    def test_a_range_with_no_upper_bound_affects_every_later_release(self) -> None:
        """An advisory with no fix bounds nothing above, so a new release is still affected."""
        adv = _advisory(ranges=(VersionRange(introduced="2.0"),))
        assert verdict(adv, "99.0").applies is True

    def test_an_unbounded_lower_bound_reads_as_the_first_release(self) -> None:
        adv = _advisory(ranges=(VersionRange(introduced="0", fixed="3.0"),))
        result = verdict(adv, "0.1")
        assert result.applies is True
        assert "the first release" in result.basis

    def test_a_release_is_weighed_against_every_interval(self) -> None:
        """A second interval must still be reached when the first one misses."""
        adv = _advisory(
            ranges=(
                VersionRange(introduced="1.0", fixed="1.5"),
                VersionRange(introduced="2.0", fixed="2.5"),
            )
        )
        assert verdict(adv, "2.1").applies is True


class TestExplicitVersions:
    def test_a_listed_version_is_affected(self) -> None:
        adv = _advisory(versions=("1.2.3",))
        assert verdict(adv, "1.2.3").applies is True

    def test_a_listed_version_matches_across_spellings(self) -> None:
        """A feed may list 1.0 where a lockfile pins 1.0.0; PEP 440 calls those one release."""
        adv = _advisory(versions=("1.0",))
        assert verdict(adv, "1.0.0").applies is True

    def test_an_unlisted_version_is_not_affected(self) -> None:
        adv = _advisory(versions=("1.2.3",))
        assert verdict(adv, "1.2.4").applies is False

    def test_an_unreadable_entry_does_not_hide_a_readable_one(self) -> None:
        """One malformed claim says nothing about the others, so the list is not abandoned."""
        adv = _advisory(versions=("not-a-version", "1.2.3"))
        assert verdict(adv, "1.2.3").applies is True


class TestUnknownVerdicts:
    def test_a_pin_that_is_not_a_version_cannot_be_weighed(self) -> None:
        """A lockfile may name a URL or a local path; neither can be placed in a range."""
        adv = _advisory(ranges=(VersionRange(introduced="0", fixed="3.0"),))
        result = verdict(adv, "file:///opt/wheels/certifi.whl")
        assert result.applies is None
        assert "PEP 440" in result.basis

    def test_an_unreadable_bound_cannot_clear_a_release(self) -> None:
        """Treating an unreadable bound as a miss would clear a pin nobody tested."""
        adv = _advisory(ranges=(VersionRange(introduced="0", fixed="latest"),))
        result = verdict(adv, "1.0")
        assert result.applies is None

    def test_an_advisory_that_bounds_nothing_decides_nothing(self) -> None:
        adv = _advisory()
        result = verdict(adv, "1.0")
        assert result.applies is None
        assert "bounds nothing" in result.basis


class TestBasis:
    def test_a_hit_names_the_release_that_carries_the_fix(self) -> None:
        adv = _advisory(ranges=(VersionRange(introduced="2.0", fixed="3.0"),))
        assert "3.0" in verdict(adv, "2.5").basis

    def test_a_miss_names_the_fix_that_cleared_the_pin(self) -> None:
        """An operator reading "not affected" should not have to open the advisory to see why."""
        adv = _advisory(ranges=(VersionRange(introduced="2.0", fixed="3.0"),))
        assert "fixed in 3.0" in verdict(adv, "4.0").basis

    def test_a_miss_against_an_unfixed_advisory_names_no_fix(self) -> None:
        """An advisory bounded only by last_affected has no fix to name, and must not invent one."""
        adv = _advisory(ranges=(VersionRange(introduced="2.0", last_affected="3.0"),))
        basis = verdict(adv, "1.0").basis
        assert "outside every affected range" in basis
        assert "fixed in" not in basis

    def test_every_verdict_carries_the_advisory_it_rests_on(self) -> None:
        """The advisory travels with the verdict so a report can attribute its text."""
        adv = _advisory()
        assert verdict(adv, "1.0").advisory is adv


class TestSourceState:
    def test_age_is_measured_from_the_export_not_the_download(self) -> None:
        now = datetime(2026, 11, 1, tzinfo=UTC)
        state = SourceState(available=True, reason="loaded", exported_at=now - timedelta(days=9))
        assert state.age_days(now) == 9

    def test_an_unknown_export_time_has_no_age(self) -> None:
        state = SourceState(available=True, reason="loaded")
        assert state.age_days(datetime(2026, 11, 1, tzinfo=UTC)) is None

    def test_a_future_export_time_is_reported_not_clamped(self) -> None:
        """A negative age is a clock problem or a tampered manifest; hiding it helps neither."""
        now = datetime(2026, 11, 1, tzinfo=UTC)
        state = SourceState(available=True, reason="loaded", exported_at=now + timedelta(days=3))
        age = state.age_days(now)
        assert age is not None and age < 0


class TestNullSource:
    def test_it_reports_itself_unavailable(self) -> None:
        assert NullSource().state().available is False

    def test_its_reason_tells_the_operator_what_to_run(self) -> None:
        assert "advisories update" in NullSource().state().reason

    def test_it_holds_nothing(self) -> None:
        assert NullSource().advisories_for("certifi") == ()

    def test_it_satisfies_the_port(self) -> None:
        """The default has to be usable wherever a real source is, or callers grow a None branch."""
        from mas_sentry.advisories import AdvisorySource

        assert isinstance(NullSource(), AdvisorySource)


class TestFakeSourceSatisfiesThePort:
    """A fake is what every later test of the detector will run against.

    Pinned here so the port cannot drift into something only a network client can
    satisfy, which is how an offline check quietly acquires a socket.
    """

    def test_a_dict_backed_source_is_enough(self) -> None:
        from mas_sentry.advisories import AdvisorySource

        class FakeSource:
            def __init__(self, holdings: dict[str, tuple[Advisory, ...]]) -> None:
                self._holdings = holdings

            def state(self) -> SourceState:
                return SourceState(
                    available=True,
                    reason="fake",
                    exported_at=datetime(2026, 11, 1, tzinfo=UTC),
                    record_count=len(self._holdings),
                )

            def advisories_for(self, package: str) -> tuple[Advisory, ...]:
                return self._holdings.get(package, ())

        source = FakeSource({"certifi": (_advisory(),)})
        assert isinstance(source, AdvisorySource)
        assert source.advisories_for("certifi")
        assert source.advisories_for("httpx") == ()


@pytest.mark.parametrize(
    ("pinned", "expected"),
    [
        ("2026.5.20", True),
        ("2026.10.18", True),
        ("2026.10.19", False),
        ("2026.10.23", False),
    ],
)
def test_the_certifi_advisory_this_work_started_from(pinned: str, expected: bool) -> None:
    """PYSEC-2026-4320 against the pins the repository actually carried.

    Run #41 of the supply-chain workflow failed on 2026.5.20 and the fix moved
    the lockfile to 2026.10.23. The advisory names 2026.10.19 as the fixed
    release, so 2026.10.18 - which closed the root but not the chain - is still
    affected. Pinning the real case keeps the range rules honest against an
    advisory nobody here wrote.
    """
    adv = Advisory(
        id="PYSEC-2026-4320",
        package="certifi",
        summary="certifi bundles the emSign ECC Root CA - G3 root; eMudhra intermediates are compromised",
        references=("https://osv.dev/vulnerability/PYSEC-2026-4320",),
        ranges=(VersionRange(introduced="0", fixed="2026.10.19"),),
    )
    assert verdict(adv, pinned).applies is expected
