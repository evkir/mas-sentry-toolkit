#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Generate coverage badge URL for README.
Run after: pytest --cov=mas_sentry --cov-report=term-missing
"""
import subprocess
import sys
import re


def get_coverage_percent() -> int:
    result = subprocess.run(
        ["python", "-m", "pytest", "--cov=mas_sentry",
         "--cov-report=term", "-q", "--no-header"],
        capture_output=True, text=True
    )
    output = result.stdout + result.stderr
    match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", output)
    if match:
        return int(match.group(1))
    return 0


def coverage_color(pct: int) -> str:
    if pct >= 80:
        return "brightgreen"
    elif pct >= 60:
        return "yellow"
    elif pct >= 40:
        return "orange"
    return "red"


def main():
    pct = get_coverage_percent()
    color = coverage_color(pct)
    badge_url = f"https://img.shields.io/badge/coverage-{pct}%25-{color}"
    markdown = f"![coverage]({badge_url})"
    print(f"\nCoverage: {pct}%")
    print(f"Badge URL: {badge_url}")
    print(f"Markdown:  {markdown}")
    print("\nAdd this line to your README.md badges section.")
    return 0 if pct >= 70 else 1


if __name__ == "__main__":
    sys.exit(main())
