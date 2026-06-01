# SPDX-License-Identifier: AGPL-3.0-or-later
"""OWASP Agentic Top 10 (2026) detection modules.

Each ASI submodule exposes `run(target, **opts) -> list[AgenticFinding]`.
"""

from .base import AgenticFinding, AsiCategory

__all__ = ["AgenticFinding", "AsiCategory"]
