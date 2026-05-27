# SPDX-License-Identifier: AGPL-3.0-or-later
"""Active probe: drop a benign canary command into a vulnerable STDIO config.

We never run destructive commands. The probe appends `; touch <uuid-canary>` to
the configured command and confirms exploitability by file existence.

Design note — why this module spawns a shell while `transport_stdio` never does:
`transport_stdio` is our *client*; it must stay injection-proof. This probe, by
contrast, deliberately *emulates a vulnerable MCP host* — a host whose
`StdioServerParameters` builder concatenates untrusted input and hands it to a
shell. Reproducing that unsafe behaviour in an isolated, opt-in module is the
only honest way to confirm a real sink. The payload is a non-destructive
`touch`; nothing else is ever executed.
"""

from __future__ import annotations

import contextlib
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class InjectionProbeResult:
    confirmed: bool
    canary_path: str
    server_responded: bool
    detail: str = ""


def _build_command(server_command: str | list[str]) -> str:
    """Render the audited command as a single shell string."""
    if isinstance(server_command, list):
        return " ".join(server_command)
    return server_command


def probe_via_config_field(
    server_command: str | list[str],
    extra_env: dict[str, str] | None = None,
    timeout: float = 5.0,
) -> InjectionProbeResult:
    """Emulate an unsafe MCP host: concatenate a canary suffix and shell-execute.

    Legal use case: auditing your own MCP host's `StdioServerParameters` builder.
    """
    canary = Path(tempfile.gettempdir()) / f"mas-sentry-canary-{uuid.uuid4().hex}.flag"
    base = _build_command(server_command)
    injected = f"{base} ; touch {canary}"

    responded = False
    detail = ""
    try:
        # Audited behaviour under test (see module docstring); not a tooling bug.
        proc = subprocess.run(  # noqa: S602  # nosec B602
            injected,
            shell=True,
            env=extra_env,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        responded = proc.returncode == 0
        detail = f"exit={proc.returncode}"
    except subprocess.TimeoutExpired:
        detail = "timeout (server kept running — canary still checked)"
    except OSError as e:
        detail = f"spawn failed: {e}"

    confirmed = canary.exists()
    if confirmed:
        with contextlib.suppress(OSError):
            canary.unlink()
    return InjectionProbeResult(
        confirmed=confirmed,
        canary_path=str(canary),
        server_responded=responded,
        detail=detail,
    )
