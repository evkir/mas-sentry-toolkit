# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI entry point. Typer-based, grouped commands."""

import typer

from .abfp_cmd import app as abfp_app

app = typer.Typer(help="MAS-Sentry: unified MAS security toolkit", no_args_is_help=True)
app.add_typer(abfp_app, name="abfp", help="Agent Behavioral Fingerprinting (Phases 1-5)")


@app.callback()
def main() -> None:
    """Top-level CLI."""
