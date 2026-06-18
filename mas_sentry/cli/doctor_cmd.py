# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import importlib
import os
import shutil
import sys

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer()
console = Console()

# Runtime deps mirrored from pyproject [project].dependencies.
_DEPS = [
    "paho.mqtt.client",
    "pika",
    "rich",
    "typer",
    "pydantic",
    "jinja2",
    "httpx",
    "networkx",
    "scipy",
    "structlog",
]


@app.callback(invoke_without_command=True)
def doctor() -> None:
    """Check Python version, deps, optional tools, and scope-confirmation env."""
    table = Table(title="mas-sentry doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")

    py_ok = sys.version_info >= (3, 11)
    table.add_row(
        "Python",
        "OK" if py_ok else "FAIL",
        ".".join(map(str, sys.version_info[:3])),
    )

    for mod in _DEPS:
        ok = _can_import(mod)
        table.add_row(
            f"Import: {mod}",
            "OK" if ok else "MISSING",
            "" if ok else "pip install -e .",
        )

    table.add_row(
        "docker",
        "OK" if shutil.which("docker") else "WARN",
        "lab scenarios use docker compose",
    )
    table.add_row(
        "mosquitto_pub",
        "OK" if shutil.which("mosquitto_pub") else "WARN",
        "optional for manual MQTT testing",
    )

    scope = os.environ.get("MAS_SENTRY_SCOPE_CONFIRMED")
    table.add_row(
        "Scope flag",
        "SET" if scope else "UNSET",
        "Required only for non-lab targets; lab works either way",
    )

    console.print(table)


def _can_import(mod: str) -> bool:
    try:
        importlib.import_module(mod)
        return True
    except ImportError:
        return False
