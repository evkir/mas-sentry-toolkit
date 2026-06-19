# SPDX-License-Identifier: AGPL-3.0-or-later
"""Module entry point: `python -m mas_sentry` runs the same CLI as `mas-sentry`."""

from mas_sentry.cli import app

if __name__ == "__main__":
    app()
