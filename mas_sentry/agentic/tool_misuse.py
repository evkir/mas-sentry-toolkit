# SPDX-License-Identifier: AGPL-3.0-or-later
"""ASI02 — Tool Misuse & Exploitation.

We detect three sub-classes from a tool inventory:
1. Destructive primitives present without confirmation gating.
2. Out-of-scope tools (file delete + network egress in same agent).
3. Argument-injection-friendly tools (shell-passing).
4. Admin-class tools without scoping.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base import AgenticFinding, AsiCategory

DESTRUCTIVE_KEYWORDS = {
    "delete",
    "remove",
    "drop",
    "truncate",
    "kill",
    "shutdown",
    "reboot",
    "wipe",
    "force_push",
    "rm_rf",
    "destroy",
}
NETWORK_KEYWORDS = {"http", "fetch", "request", "send", "upload", "publish", "email"}
SHELL_KEYWORDS = {"exec", "shell", "run_cmd", "subprocess", "system", "eval"}
ADMIN_KEYWORDS = {"admin", "root", "sudo", "privileged", "elevated"}


@dataclass(frozen=True, slots=True)
class ToolInventoryEntry:
    name: str
    description: str = ""
    requires_confirmation: bool = False


def _has_kw(s: str, kws: set[str]) -> bool:
    low = s.lower()
    return any(k in low for k in kws)


def audit_tool_inventory(tools: list[ToolInventoryEntry], target: str) -> list[AgenticFinding]:
    findings: list[AgenticFinding] = []
    names = {t.name.lower() for t in tools}

    # 1. Destructive without confirmation
    for t in tools:
        haystack = t.name + " " + t.description
        if _has_kw(haystack, DESTRUCTIVE_KEYWORDS) and not t.requires_confirmation:
            findings.append(
                AgenticFinding(
                    asi=AsiCategory.TOOL_MISUSE,
                    severity="HIGH",
                    title=f"Destructive tool without confirmation gate: {t.name}",
                    detail=("Tool can cause irreversible damage but does not require user confirmation"),
                    target=target,
                    evidence={"tool": t.name, "description": t.description[:200]},
                    cwe="CWE-269",
                )
            )

    # 2. Combined surface — destructive + network = exfiltration risk
    has_destructive = any(_has_kw(n, DESTRUCTIVE_KEYWORDS) for n in names)
    has_network = any(_has_kw(n, NETWORK_KEYWORDS) for n in names)
    if has_destructive and has_network:
        findings.append(
            AgenticFinding(
                asi=AsiCategory.TOOL_MISUSE,
                severity="MEDIUM",
                title="Agent grants destructive + network primitives simultaneously",
                detail=("Combination enables data-wipe + exfiltration in a single agent context"),
                target=target,
                evidence={
                    "destructive_tools": sorted(n for n in names if _has_kw(n, DESTRUCTIVE_KEYWORDS)),
                    "network_tools": sorted(n for n in names if _has_kw(n, NETWORK_KEYWORDS)),
                },
            )
        )

    # 3. Shell-passing tools (argument injection risk)
    for t in tools:
        if _has_kw(t.name, SHELL_KEYWORDS):
            findings.append(
                AgenticFinding(
                    asi=AsiCategory.TOOL_MISUSE,
                    severity="HIGH",
                    title=f"Shell-passing tool present: {t.name}",
                    detail=("Tool name implies arbitrary command execution; argument injection likely"),
                    target=target,
                    evidence={"tool": t.name},
                    cwe="CWE-78",
                )
            )

    # 4. Admin tools without scoping
    for t in tools:
        haystack = t.name + " " + t.description
        if _has_kw(haystack, ADMIN_KEYWORDS):
            findings.append(
                AgenticFinding(
                    asi=AsiCategory.TOOL_MISUSE,
                    severity="MEDIUM",
                    title=f"Admin-class tool exposed: {t.name}",
                    detail=("Tool advertises privileged operation; verify scoping and approval flow"),
                    target=target,
                    evidence={"tool": t.name, "description": t.description[:160]},
                )
            )

    return findings
