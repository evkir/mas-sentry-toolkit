# SPDX-License-Identifier: AGPL-3.0-or-later
"""Append-only JSONL audit log. One line per privileged action."""

from __future__ import annotations

import contextlib
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any

_DEFAULT = Path("~/.mas-sentry/audit.jsonl").expanduser()
_LOCK = Lock()


def write(entry: dict[str, Any], path: Path = _DEFAULT) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    enriched = {**entry, "ts": datetime.now(UTC).isoformat(timespec="seconds"), "pid": os.getpid()}
    with _LOCK, path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(enriched, default=str) + "\n")
    # Restrict to owner read+write (0600); no access for group/other.
    with contextlib.suppress(OSError):
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def tail(n: int = 50, path: Path = _DEFAULT) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-n:]
    out: list[dict[str, Any]] = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
