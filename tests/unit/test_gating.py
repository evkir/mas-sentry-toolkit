# SPDX-License-Identifier: AGPL-3.0-or-later
"""The CI gate: which findings should fail the process that ran the scan."""

from __future__ import annotations

import pytest

from mas_sentry.core.finding import Severity
from mas_sentry.core.gating import FINDINGS_EXIT_CODE, THRESHOLD_NAMES, gate, parse_severity


def test_a_threshold_name_is_case_insensitive() -> None:
    assert parse_severity("high") is Severity.HIGH
    assert parse_severity("  Critical ") is Severity.CRITICAL


def test_an_unknown_threshold_names_the_valid_ones() -> None:
    """The message is what a CLI shows instead of a traceback, so it has to be usable."""
    with pytest.raises(ValueError, match="valid: info, low, medium, high, critical"):
        parse_severity("warn")


def test_every_severity_is_a_valid_threshold() -> None:
    """The option's help text lists these, so the two must not drift apart."""
    assert THRESHOLD_NAMES == ("info", "low", "medium", "high", "critical")
    for name in THRESHOLD_NAMES:
        assert parse_severity(name).value == name.upper()


def test_a_severity_at_the_threshold_trips_it() -> None:
    result = gate(["MEDIUM"], Severity.MEDIUM)
    assert result.triggered == ("MEDIUM",)
    assert result.failed is True


def test_a_severity_below_the_threshold_does_not() -> None:
    result = gate(["INFO", "LOW"], Severity.MEDIUM)
    assert result.triggered == ()
    assert result.failed is False


def test_only_the_rows_at_or_above_the_threshold_are_reported() -> None:
    """The command prints these, so the gate must not claim rows that did not trip it."""
    result = gate(["INFO", "HIGH", "LOW", "CRITICAL"], Severity.HIGH)
    assert result.triggered == ("HIGH", "CRITICAL")


def test_no_findings_never_trips() -> None:
    assert gate([], Severity.INFO).failed is False


def test_a_severity_the_gate_cannot_read_fails_closed() -> None:
    """A gate that ignores a row it does not understand lets through what it exists to catch.

    The MCP scan still emits rows whose `severity` is a plain `str`, so a module
    bug can put a non-severity there. Skipping it would make the gate pass on a
    row nobody has assessed.
    """
    result = gate(["warn"], Severity.CRITICAL)
    assert result.triggered == ()
    assert result.unreadable == ("warn",)
    assert result.failed is True


def test_an_unreadable_value_is_kept_apart_from_a_real_trip() -> None:
    """Both fail the gate; the command says which happened, so a red run is not a mystery."""
    result = gate(["CRITICAL", "", "nonsense"], Severity.HIGH)
    assert result.triggered == ("CRITICAL",)
    assert result.unreadable == ("", "nonsense")


def test_the_findings_exit_code_is_not_the_usage_error_code() -> None:
    """A pipeline has to tell "this scan found problems" from "this job is broken"."""
    assert FINDINGS_EXIT_CODE == 1
    assert FINDINGS_EXIT_CODE != 2
