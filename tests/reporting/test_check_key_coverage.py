# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every check key the MCP scan can emit is accounted for, and reaches SARIF.

The conversion path is generic - `from_mcp_check` maps any `{check, severity,
detail}` entry - so a new key reaches every report format on its own. What it
does not reach on its own is the taxonomy: `_MCP_CHECK_TAGS` is written by
hand, and a weakness added without an entry there ships as a SARIF result with
no CWE, invisible to the filters an operator triages with. Nothing said so
until this module: the exemption list was a comment, and three keys added after
it was written appeared in neither it nor the table.
"""

from __future__ import annotations

import importlib
import json
import pkgutil
import re
from pathlib import Path

from mas_sentry.core.adapters import _MCP_CHECK_TAGS, _MCP_UNTAGGED_CHECKS, from_mcp_check
from mas_sentry.reporting.sarif import write_sarif

MCP_PACKAGE = "mas_sentry.protocols.mcp"
AUDIT_PACKAGE = f"{MCP_PACKAGE}.audit"

# The three shapes a check key is written in. Read from source on purpose: a
# key nobody registered is exactly the key no import would reach.
_ROW_KEY = re.compile(r'"check":\s*"([a-z_]+)"')
_FINDING_KIND = re.compile(r'kind="([a-z_]+)"')


def _source_root() -> Path:
    return Path(importlib.import_module(MCP_PACKAGE).__file__ or "").parent


def emitted_check_keys() -> set[str]:
    """Every key the MCP surface can put in a report."""
    root = _source_root()
    keys: set[str] = set()
    keys.update(_ROW_KEY.findall((root / "runtime.py").read_text()))
    audit = importlib.import_module(AUDIT_PACKAGE)
    for path in (root / "audit").glob("*.py"):
        keys.update(_FINDING_KIND.findall(path.read_text()))
    for info in pkgutil.iter_modules(audit.__path__):
        module = importlib.import_module(f"{AUDIT_PACKAGE}.{info.name}")
        for name in dir(module):
            if not name.endswith("_CHECK"):
                continue
            value = getattr(module, name)
            if isinstance(value, str) and value:
                keys.add(value)
    return keys


def test_the_scan_emits_the_keys_this_module_thinks_it_does() -> None:
    """A cheap sanity check on the collector before anything is asserted with it."""
    keys = emitted_check_keys()
    for expected in ("ssrf", "tool_poisoning", "task_undeclared", "scan_budget_exhausted", "target_unreachable"):
        assert expected in keys, f"the collector missed {expected}; it can no longer speak for the surface"


def test_every_key_is_either_classified_or_deliberately_not() -> None:
    """The forcing function.

    A new weakness key has to be given its ASI/CWE/STRIDE lenses, or be named
    as a coverage note. Landing in neither means it ships untagged and nothing
    notices, which is how the comment this replaced fell behind.
    """
    unaccounted = sorted(emitted_check_keys() - set(_MCP_CHECK_TAGS) - _MCP_UNTAGGED_CHECKS)
    assert not unaccounted, (
        f"these check keys are in neither _MCP_CHECK_TAGS nor _MCP_UNTAGGED_CHECKS: {unaccounted}. "
        "Give each one its taxonomy, or name it as a coverage note that carries none"
    )


def test_no_key_is_both_classified_and_exempt() -> None:
    overlap = sorted(set(_MCP_CHECK_TAGS) & _MCP_UNTAGGED_CHECKS)
    assert not overlap, f"these keys claim a taxonomy and an exemption at once: {overlap}"


def test_every_key_survives_the_conversion_to_sarif(tmp_path: Path) -> None:
    """One synthetic row per key, through the adapter and out the other side."""
    keys = sorted(emitted_check_keys())
    findings = [
        from_mcp_check({"check": key, "severity": "MEDIUM", "detail": f"synthetic row for {key}"}, "rig")
        for key in keys
    ]
    out = tmp_path / "all.sarif"
    write_sarif([f.to_dict() for f in findings], out)

    report = json.loads(out.read_text())
    run = report["runs"][0]
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    for key in keys:
        assert f"MAS-SENTRY-MCP.{key.upper()}" in rule_ids, f"{key} produced no SARIF rule"
    assert len(run["results"]) == len(keys), "a row was dropped between the adapter and the results array"


def test_a_classified_key_carries_its_lenses_into_the_finding() -> None:
    """The taxonomy is the reason the table exists; check it arrives."""
    finding = from_mcp_check({"check": "ssrf", "severity": "CRITICAL", "detail": "x"}, "rig")
    assert "CWE-918" in finding.tags
    assert "ssrf" in finding.tags


def test_an_exempt_key_carries_nothing_but_its_name() -> None:
    """Pinned in both directions: a coverage note must not gain a CWE by accident."""
    finding = from_mcp_check({"check": "target_unreachable", "severity": "MEDIUM", "detail": "x"}, "rig")
    assert finding.tags == ["target_unreachable"]
