# SPDX-License-Identifier: AGPL-3.0-or-later
"""Global CLI options applied via the root callback."""

from __future__ import annotations

import logging
import os

import structlog


def configure_logging(verbose: bool = False, quiet: bool = False, no_color: bool = False) -> None:
    if no_color:
        os.environ["NO_COLOR"] = "1"
    level = logging.WARNING
    if verbose:
        level = logging.DEBUG
    if quiet:
        level = logging.ERROR
    logging.basicConfig(level=level, format="%(message)s")
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(level),
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=not no_color),
        ],
    )
