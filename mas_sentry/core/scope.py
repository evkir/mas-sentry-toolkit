# SPDX-License-Identifier: AGPL-3.0-or-later
"""Centralised scope-guard. Every active probe goes through this."""

from __future__ import annotations

import os
from urllib.parse import urlparse

LAB_HOSTS = {"localhost", "127.0.0.1", "::1"}
LAB_SUFFIXES = (".lab", ".test", ".local")
SCOPE_ENV = "MAS_SENTRY_SCOPE_CONFIRMED"


class ScopeViolation(PermissionError):
    pass


def is_lab_target(target: str) -> bool:
    if not target:
        return False
    if target.startswith("stdio://"):
        return True  # local subprocess
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = (parsed.hostname or "").lower()
    if host in LAB_HOSTS:
        return True
    return host.endswith(LAB_SUFFIXES)


def assert_in_scope(target: str, confirmed: bool = False) -> None:
    if is_lab_target(target):
        return
    if confirmed:
        return
    if os.environ.get(SCOPE_ENV) == "1":
        return
    raise ScopeViolation(
        f"Target '{target}' is outside the lab allowlist. "
        f"Pass --confirm-scope or export {SCOPE_ENV}=1 if you have written authorisation."
    )
