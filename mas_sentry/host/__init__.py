# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agent-host posture: the configuration on the operator's own machine.

A scanned MCP server is one half of the surface. The other half is the host
that launches it, and in the 2026 CVE corpus that half is where a third of the
reported compromises happened. It is not reachable by connecting to anything,
so it has its own package.
"""

from .discovery import HostConfig, locate, present, supported_hosts
from .inventory import EnvEntry, InputDecl, Inventory, ServerEntry, ValueShape, read, shape_of

__all__ = [
    "EnvEntry",
    "HostConfig",
    "InputDecl",
    "Inventory",
    "ServerEntry",
    "ValueShape",
    "locate",
    "present",
    "read",
    "shape_of",
    "supported_hosts",
]
