# SPDX-License-Identifier: AGPL-3.0-or-later
"""Guard: the version that ships has a changelog section of its own.

Releases are cut by pushing a `v*` tag, which builds and publishes whatever
pyproject says the version is. Nothing connected that number to CHANGELOG.md,
so a tag could put a version on PyPI whose changes are described nowhere -
and the reverse, a bump that leaves its entries sitting under [Unreleased]
where no reader of the release looks.

This is the same class as the check-key registry: a convention held by
remembering it is a convention that has already drifted somewhere.
"""

from __future__ import annotations

import re
import tomllib
from datetime import date
from pathlib import Path

from packaging.version import Version

ROOT = Path(__file__).resolve().parents[2]

# "## [0.8.0] - 2026-07-29 - Reference-SDK rigs ..." - version and date are
# fixed, the title after them is free text.
_RELEASED = re.compile(r"^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})", re.MULTILINE)


def _project_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version: str = data["project"]["version"]
    return version


def _released_sections() -> list[tuple[str, str]]:
    return _RELEASED.findall((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))


def test_the_shipping_version_is_the_newest_changelog_section() -> None:
    """A tag builds pyproject's version; that version has to be described."""
    sections = _released_sections()
    assert sections, "CHANGELOG.md holds no released section"
    assert sections[0][0] == _project_version(), (
        f"pyproject is at {_project_version()} and the newest changelog section is {sections[0][0]}: "
        "either the bump left its entries under [Unreleased] or a section was written for a version "
        "that is not the one a tag would publish"
    )


def test_released_sections_descend() -> None:
    """Out of order, the newest section is not the one at the top."""
    versions = [Version(v) for v, _ in _released_sections()]
    assert versions == sorted(versions, reverse=True), f"changelog sections are out of order: {versions}"


def test_no_release_is_dated_in_the_future() -> None:
    """A date later than today means the section was written before the release."""
    today = date.today().isoformat()
    ahead = [(v, d) for v, d in _released_sections() if d > today]
    assert not ahead, f"released sections dated in the future: {ahead}"


def test_the_unreleased_section_is_present() -> None:
    """Where the next change goes. Without it, entries land in a shipped section."""
    assert "## [Unreleased]" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
