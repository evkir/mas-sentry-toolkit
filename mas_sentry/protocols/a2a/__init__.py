# SPDX-License-Identifier: AGPL-3.0-or-later
"""Google Agent-to-Agent (A2A) protocol — minimal pentest client."""

from .client import A2AClient, A2ARpcError, AgentCard, TaskResult, TaskState

__all__ = ["A2AClient", "A2ARpcError", "AgentCard", "TaskResult", "TaskState"]
