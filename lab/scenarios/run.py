# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run a scenario YAML against the local lab.

Each step runs a shell command; if 'out' + 'expect_check' + 'expect_severity'
are present, the JSON report is loaded and checked for at least one finding
whose severity is >= expect_severity. The 'expect_check' field is logged for
context only — the actual filter is the --checks flag inside the 'run' line.

Exit codes:
    0 — all steps passed and all expectations met
    1 — a step's command exited non-zero
    2 — a step's expectation not met (file missing / no matching finding)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

# Higher number = more severe. INFO is included because mas-sentry emits it
# for fingerprint findings.
SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _sev_ge(actual: str, minimum: str) -> bool:
    a = SEVERITY_RANK.get(actual.upper(), -1)
    m = SEVERITY_RANK.get(minimum.upper(), 99)
    return a >= m


def _load_findings(out_path: Path) -> list[dict[str, Any]]:
    """mas-sentry mcp scan writes a flat JSON array of {check, severity, detail}."""
    if not out_path.exists():
        return []
    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Tolerate alternative envelope shapes.
        return data.get("protocol_findings", []) or data.get("findings", []) or []
    return []


def _check_expectation(step: dict[str, Any]) -> bool:
    out_raw = step.get("out")
    minimum = step.get("expect_severity")
    label = step.get("expect_check", "?")
    if not out_raw or not minimum:
        return True
    out_path = Path(out_raw)
    findings = _load_findings(out_path)
    # Filter to findings for this step's check, if expect_check is set.
    if label and label != "?":
        findings = [f for f in findings if f.get("check") == label]
    matched = [f for f in findings if _sev_ge(str(f.get("severity", "")), str(minimum))]
    if matched:
        top = max(matched, key=lambda f: SEVERITY_RANK.get(str(f.get("severity", "")).upper(), -1))
        detail = str(top.get("detail", ""))[:60]
        print(f"   OK  [{label}] {len(matched)} finding(s) >= {minimum} (top: {top.get('severity')} — {detail})")
        return True
    print(f"   FAIL[{label}] no finding for check={label!r} with severity>={minimum} in {out_path}")
    return False


def run(scenario_path: Path) -> int:
    sc = yaml.safe_load(scenario_path.read_text(encoding="utf-8"))
    print(f"== {sc['name']}: {sc['description']} ==")
    all_ok = True
    for i, step in enumerate(sc.get("steps", []), 1):
        cmd = step["run"]
        print(f">> [{i}] {cmd}")
        r = subprocess.run(cmd, shell=True, check=False)  # noqa: S602  # nosec B602 — controlled scenario runner
        if r.returncode != 0:
            print(f"   FAIL command exited {r.returncode}")
            return 1
        if not _check_expectation(step):
            all_ok = False
    return 0 if all_ok else 2


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: run.py <scenario.yaml>", file=sys.stderr)
        sys.exit(64)
    sys.exit(run(Path(sys.argv[1])))
