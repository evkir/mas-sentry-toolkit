# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the host-posture audit and turn it into report rows.

Locating and reading are the two halves already built. This is the entry point
that drives them over one machine and one repository and emits findings, so the
result reaches `report convert` the same way a protocol scan does.

No detector runs here yet. What this produces is the inventory itself plus the
gaps - a config that could not be read, a config whose server declarations sit
behind a key the reader does not descend into - because those are the rows that
must exist before any judgement is attached to them. A report that listed only
judgements would say nothing about the file it failed to open.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from mas_sentry.core.audit_log import write as audit_write
from mas_sentry.core.finding import Finding, Severity
from mas_sentry.reporting.structured import write_json

from .discovery import HostConfig, locate
from .inventory import Inventory, ServerEntry, read

# Top-level keys known to nest further server declarations. A key outside this
# set is recorded on the inventory row but raises no gap: `$schema` and
# `sandbox` are ordinary, and a finding on every file that carries one would be
# noise that buries the case that matters (R-2.4).
_NESTING_KEYS: Final = frozenset({"projects"})


def _server_evidence(server: ServerEntry) -> dict[str, Any]:
    """A server rendered for the evidence block: names and shapes, never values.

    Enough for a reviewer to re-derive a later verdict (R-7.2) without the
    report carrying an API key, a bearer token or a path the operator did not
    choose to publish.
    """
    return {
        "name": server.name,
        "declared_type": server.declared_type,
        "command": server.command,
        "arg_count": len(server.args),
        "url": server.url,
        "env_keys": [e.key for e in server.env],
        "env_forms": {e.key: e.shape.form for e in server.env},
        "env_file": server.env_file,
        "header_names": list(server.header_names),
        "unmodelled": sorted(server.unmodelled),
    }


def _inventory_row(inv: Inventory) -> Finding:
    src = inv.source
    count = len(inv.servers)
    return Finding(
        module="host.inventory",
        title=f"{src.host} ({src.scope}): {count} server(s) declared",
        detail=(
            f"{src.path} declares {count} MCP server(s) under the '{inv.dialect}' key. "
            f"{src.note}. Recorded as inventory, not as a problem."
        ),
        severity=Severity.INFO,
        target=str(src.path),
        tags=["host", "inventory"],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "kind": src.kind,
            "path": str(src.path),
            "resolved": str(src.resolved),
            "via_symlink": src.via_symlink,
            "dialect": inv.dialect,
            "servers": [_server_evidence(s) for s in inv.servers],
            "inputs": [
                {"id": i.input_id, "kind": i.kind, "is_password": i.is_password, "command": i.command}
                for i in inv.inputs
            ],
            "unmodelled_top_level": sorted(inv.unmodelled_top_level),
        },
    )


def _unreadable_row(inv: Inventory) -> Finding:
    """A config that exists and could not be read, recorded rather than skipped.

    An operator whose config is unreadable has the same surface as one whose
    config is hostile, and a report that omitted the file would read as a clean
    assessment of something never examined (R-2.1).
    """
    src = inv.source
    return Finding(
        module="host.enumeration_gap",
        title=f"{src.host} ({src.scope}): not assessed",
        detail=(
            f"{src.path} was not assessed: {inv.unreadable}. No server declaration was read from it, "
            "so this row is a record of a file that went unexamined - a gap, not a clean result"
        ),
        severity=Severity.MEDIUM,
        target=str(src.path),
        tags=["host", "enumeration_gap"],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "path": str(src.path),
            "resolved": str(src.resolved),
            "reason": inv.unreadable,
        },
    )


def _partly_unread_row(inv: Inventory, keys: frozenset[str]) -> Finding:
    """A file whose further server declarations sit behind an unread key.

    Claude Code keeps a per-project server map under `projects`, and a file that
    declares twenty servers there would otherwise be reported as declaring the
    handful at the top level. The count is not wrong about what it read; it is
    wrong about the file, and only this row says so.
    """
    src = inv.source
    named = ", ".join(sorted(keys))
    return Finding(
        module="host.enumeration_gap",
        title=f"{src.host} ({src.scope}): partly unread ({named})",
        detail=(
            f"{src.path} nests further server declarations under '{named}', which this reader does not "
            "descend into. The servers reported for this file are the ones outside that key, so the "
            "file is partly unassessed rather than fully read"
        ),
        severity=Severity.MEDIUM,
        target=str(src.path),
        tags=["host", "enumeration_gap"],
        evidence={
            "host": src.host,
            "scope": src.scope,
            "path": str(src.path),
            "unread_keys": sorted(keys),
            "servers_read": len(inv.servers),
        },
    )


def _nothing_found_row(target: str, checked: int) -> Finding:
    """No host config is present, stated with how many paths were examined.

    An empty finding list would be indistinguishable from an audit that never
    ran. The count is the evidence that it did.
    """
    return Finding(
        module="host.inventory",
        title="No agent-host configuration found",
        detail=(
            f"{checked} documented config path(s) were examined under {target} and none exist. "
            "This is an empty result from an audit that ran, not an audit that did not run"
        ),
        severity=Severity.INFO,
        target=target,
        tags=["host", "inventory"],
        evidence={"paths_checked": checked},
    )


def findings_for(inventories: list[Inventory], target: str, checked: int) -> list[Finding]:
    """Turn the readings into rows. Separated from I/O so it can be driven directly."""
    out: list[Finding] = []
    for inv in inventories:
        if inv.unreadable is not None:
            out.append(_unreadable_row(inv))
            continue
        out.append(_inventory_row(inv))
        nesting = inv.unmodelled_top_level & _NESTING_KEYS
        if nesting:
            out.append(_partly_unread_row(inv, nesting))
    if not out:
        out.append(_nothing_found_row(target, checked))
    return out


def run_host_audit(home: Path, project_root: Path, system: str, out: Path) -> list[Finding]:
    """Locate every documented config for this machine, read what is there, report.

    Absent paths produce no row: `locate` returns them so a caller can tell the
    table from the disk, and the caller that wants a per-host accounting of what
    is missing is not this one. What an absent path must never do is vanish
    without the report saying how many were looked at, which `_nothing_found_row`
    carries when nothing at all turned up.
    """
    located: list[HostConfig] = locate(home=home, project_root=project_root, system=system)
    inventories = [read(c) for c in located if c.exists]
    target = str(home)
    findings = findings_for(inventories, target, len(located))
    write_json(findings, target, out)
    audit_write({"action": "host_audit_done", "target": target, "findings": len(findings)})
    return findings
