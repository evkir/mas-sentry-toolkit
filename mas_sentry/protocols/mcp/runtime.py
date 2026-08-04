# SPDX-License-Identifier: AGPL-3.0-or-later
"""MCP scan orchestrator: applies all audit modules, enforces scope, logs audit trail."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mas_sentry.core.audit_log import write as audit_write
from mas_sentry.core.scope import assert_in_scope

from .audit.dns_rebind import test_dns_rebinding
from .audit.header_desync import probe_header_desync
from .audit.path_traversal import probe_arg_injection, probe_path_traversal
from .audit.resource_content import audit_resource_content, audit_resource_templates
from .audit.ssrf import probe_ssrf
from .audit.tool_drift import detect_tool_drift
from .audit.tool_poisoning import detect_tool_poisoning
from .client import McpClient
from .fingerprint import fingerprint, known_cves_for
from .transport_http import HttpConfig, open_http
from .transport_stdio import StdioConfig, open_stdio


def run_mcp_scan(
    scheme: str,
    command: str | list[str],
    target_label: str,
    checks: str,
    out: Path,
    scope_confirmed: bool,
    tool_baseline: Path | None = None,
) -> list[dict[str, Any]]:
    _enforce_scope(scheme=scheme, command=command, confirmed=scope_confirmed)
    audit_write({"action": "mcp_scan_start", "target": target_label, "checks": checks})

    findings: list[dict[str, Any]] = []

    if scheme == "stdio":
        with open_stdio(StdioConfig(command=command)) as t:
            findings.extend(
                _run_all_checks(McpClient(t), transport="stdio", checks=checks, tool_baseline=tool_baseline)
            )
    elif scheme in ("http", "https"):
        assert isinstance(command, str)  # CLI guarantees this for http(s)
        with open_http(HttpConfig(url=command)) as t:
            findings.extend(_run_all_checks(McpClient(t), transport=scheme, checks=checks, tool_baseline=tool_baseline))
            if checks in ("all", "rebind"):
                rb = test_dns_rebinding(command)
                if rb.vulnerable:
                    findings.append(
                        {
                            "check": "dns_rebind",
                            "severity": "HIGH",
                            "detail": f"Accepts Host={rb.accepted_host} Origin={rb.accepted_origin}",
                        }
                    )
    else:
        raise ValueError(f"Unsupported scheme: {scheme}")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(findings, indent=2, default=str))
    audit_write({"action": "mcp_scan_done", "target": target_label, "findings": len(findings)})
    return findings


def _desync_rows(client: McpClient) -> list[dict[str, Any]]:
    """Header/body agreement, reported per probe.

    A server that accepts an inconsistent request is the finding: a gateway in
    front of it authorizes the header while the server executes the body. Probe
    targets come from the inventory already enumerated, so nothing is sent
    against an invented tool name whose "method not found" would prove nothing.
    """
    tools = client.list_tools()
    resources = client.list_resources()
    findings = probe_header_desync(
        client,
        tool_name=tools[0].name if tools else "",
        resource_uri=resources[0].uri if resources else "",
    )
    rows: list[dict[str, Any]] = []
    for f in findings:
        if f.status == "accepted":
            rows.append({"check": "header_body_desync", "severity": "HIGH", "detail": f"{f.probe}: {f.detail}"})
        elif f.status == "inconclusive":
            rows.append(
                {
                    "check": "header_body_desync",
                    "severity": "INFO",
                    "detail": f"{f.probe}: inconclusive - the server refused for an unrelated reason",
                }
            )
    if findings and not rows:
        rows.append(
            {
                "check": "header_body_desync",
                "severity": "INFO",
                "detail": f"header/body agreement enforced on all {len(findings)} probes",
            }
        )
    return rows


def _run_all_checks(
    client: McpClient, transport: str, checks: str, tool_baseline: Path | None = None
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    fp = fingerprint(client, transport_name=transport)
    out.append(
        {
            "check": "fingerprint",
            "severity": "INFO",
            "detail": f"{fp.name} {fp.version} ({fp.tool_count} tools)",
        }
    )
    for impl in fp.suspected_impls:
        for cve in known_cves_for(impl):
            out.append({"check": "known_cve", "severity": "HIGH", "detail": f"{impl}: {cve}"})

    if checks in ("all", "poisoning"):
        for pf in detect_tool_poisoning(client):
            out.append(
                {
                    "check": "tool_poisoning",
                    "severity": pf.severity,
                    "detail": f"{pf.tool}: {'; '.join(pf.reasons)}",
                }
            )

    if checks in ("all", "resources"):
        for rf in audit_resource_content(client):
            signals = list(rf.injection_patterns) + list(rf.exfil_channels)
            out.append(
                {
                    "check": "resource_content",
                    "severity": rf.severity,
                    "detail": f"{rf.uri}: {'; '.join(signals)}",
                }
            )
        for rt in audit_resource_templates(client):
            signals = list(rt.injection_patterns) + list(rt.exfil_channels)
            out.append(
                {
                    "check": "resource_template",
                    "severity": rt.severity,
                    "detail": f"{rt.uri}: {'; '.join(signals)}",
                }
            )

    if checks in ("all", "desync"):
        out.extend(_desync_rows(client))

    if checks in ("all", "ssrf"):
        for sf in probe_ssrf(client):
            if sf.status == "OK":
                out.append(
                    {
                        "check": "ssrf",
                        "severity": "CRITICAL",
                        "detail": f"{sf.tool} -> {sf.url}",
                    }
                )

    if checks in ("all", "traversal"):
        for tf in probe_path_traversal(client):
            if tf.confirmed:
                out.append(
                    {
                        "check": "path_traversal",
                        "severity": "HIGH",
                        "detail": f"{tf.tool}: {tf.payload}",
                    }
                )
        for tf in probe_arg_injection(client):
            if tf.confirmed:
                out.append(
                    {
                        "check": "arg_injection",
                        "severity": "CRITICAL",
                        "detail": f"{tf.tool}: {tf.payload}",
                    }
                )

    if checks in ("all", "drift"):
        for df in detect_tool_drift(client, tool_baseline):
            out.append({"check": df.kind, "severity": df.severity, "detail": df.detail})

    # A call the server suspended is not a call that came back clean. Every
    # probe above reads its verdict off a response body, and a suspended call
    # carries none, so without this row the report shows a tool that was never
    # exercised as one that was exercised and held.
    for suspended in client.input_required:
        out.append({"check": "input_required", "severity": suspended.severity, "detail": suspended.detail})

    # Reported last, after every auditor has had its chance to list something.
    # A surface that refused to enumerate produced no findings for a reason
    # that is not "it was clean", and that distinction has to survive into the
    # report or the scan quietly overstates its own coverage.
    for issue in client.enumeration_issues:
        out.append({"check": "enumeration_gap", "severity": issue.severity, "detail": issue.detail})

    return out


def _enforce_scope(scheme: str, command: str | list[str], confirmed: bool) -> None:
    """Thin wrapper over the central scope-guard, kept for the MCP scheme/command shape."""
    if scheme == "stdio":
        return  # local subprocess: always in scope
    if scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {scheme}")
    assert isinstance(command, str)
    assert_in_scope(command, confirmed=confirmed)
