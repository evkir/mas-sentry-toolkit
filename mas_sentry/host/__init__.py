# SPDX-License-Identifier: AGPL-3.0-or-later
"""Agent-host posture: the configuration on the operator's own machine.

A scanned MCP server is one half of the surface. The other half is the host
that launches it, and in the 2026 CVE corpus that half is where a third of the
reported compromises happened. It is not reachable by connecting to anything,
so it has its own package.
"""

from .discovery import HostConfig, locate, present, supported_hosts

__all__ = ["HostConfig", "locate", "present", "supported_hosts"]
