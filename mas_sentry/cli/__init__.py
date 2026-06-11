# SPDX-License-Identifier: AGPL-3.0-or-later
"""CLI entry point. Typer-based, grouped commands."""

import typer

from .abfp_cmd import app as abfp_app
from .agentic_cmd import app as agentic_app
from .doctor_cmd import app as doctor_app
from .mcp_cmd import app as mcp_app
from .report_cmd import app as report_app

app = typer.Typer(help="MAS-Sentry: unified MAS security toolkit", no_args_is_help=True)
app.add_typer(abfp_app, name="abfp", help="Agent Behavioral Fingerprinting (Phases 1-5)")
app.add_typer(mcp_app, name="mcp", help="Model Context Protocol auditing")
app.add_typer(agentic_app, name="agentic", help="OWASP Agentic Top 10 (2026) scans")
app.add_typer(report_app, name="report", help="Convert findings to report formats")
app.add_typer(doctor_app, name="doctor", help="Environment self-check")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug-level logging"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Errors only"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colors"),
) -> None:
    """Top-level CLI."""
    from .global_opts import configure_logging

    configure_logging(verbose=verbose, quiet=quiet, no_color=no_color)
