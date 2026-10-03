# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agent-host posture: the configuration on the operator's own machine.

A scanned MCP server is one half of the surface. The other half is the host
that launches it, and in the 2026 CVE corpus that half is where a third of the
reported compromises happened. It is not reachable by connecting to anything,
so it has its own package.
"""

from .credentials import credential_findings
from .discovery import HostConfig, PathExposure, locate, present, supported_hosts
from .executable import surface_findings
from .integrity import integrity_findings
from .inventory import InputDecl, Inventory, ServerEntry, read
from .launch_spec import PinVerdict, launch_findings, verdict_for
from .precedence import cross_scope_findings
from .runtime import findings_for, run_host_audit
from .surface import ExecutableSurface, HelperCommand, HookHandler, ServerApprovals, read_surface
from .taxonomy import HOST_LENSES, HOST_UNLENSED, lensed
from .trust import trust_findings
from .values import CREDENTIAL_PREFIXES, EnvEntry, ValueShape, classify, shape_of

__all__ = [
    "CREDENTIAL_PREFIXES",
    "HOST_LENSES",
    "HOST_UNLENSED",
    "EnvEntry",
    "ExecutableSurface",
    "HelperCommand",
    "HookHandler",
    "HostConfig",
    "InputDecl",
    "Inventory",
    "PathExposure",
    "PinVerdict",
    "ServerApprovals",
    "ServerEntry",
    "ValueShape",
    "classify",
    "credential_findings",
    "cross_scope_findings",
    "findings_for",
    "integrity_findings",
    "launch_findings",
    "lensed",
    "locate",
    "present",
    "read",
    "read_surface",
    "run_host_audit",
    "shape_of",
    "supported_hosts",
    "surface_findings",
    "trust_findings",
    "verdict_for",
]
