# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agent-host posture: the configuration on the operator's own machine.

A scanned MCP server is one half of the surface. The other half is the host
that launches it, and in the 2026 CVE corpus that half is where a third of the
reported compromises happened. It is not reachable by connecting to anything,
so it has its own package.
"""

from .discovery import HostConfig, locate, present, supported_hosts
from .executable import surface_findings
from .inventory import EnvEntry, InputDecl, Inventory, ServerEntry, read
from .precedence import cross_scope_findings
from .runtime import findings_for, run_host_audit
from .surface import ExecutableSurface, HelperCommand, HookHandler, read_surface
from .values import ValueShape, shape_of

__all__ = [
    "EnvEntry",
    "ExecutableSurface",
    "HelperCommand",
    "HookHandler",
    "HostConfig",
    "InputDecl",
    "Inventory",
    "ServerEntry",
    "ValueShape",
    "cross_scope_findings",
    "findings_for",
    "locate",
    "present",
    "read",
    "read_surface",
    "run_host_audit",
    "shape_of",
    "supported_hosts",
    "surface_findings",
]
