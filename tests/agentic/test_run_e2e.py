# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end tests for the static agentic scan and its CLI wiring."""

import base64
import json
import time
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from mas_sentry.agentic.run import run_static_scan
from mas_sentry.agentic.tool_misuse import ToolInventoryEntry
from mas_sentry.agentic.trust_exploit import AgentResponse
from mas_sentry.cli import app

runner = CliRunner()


def _jwt(payload: dict[str, Any]) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    return f"{header}.{body}."


def _asis(findings: list) -> set[str]:
    return {t for f in findings for t in f.tags if t.startswith("ASI")}


# ─────────────── run_static_scan ───────────────


def test_static_scan_finds_tool_misuse_and_supply_chain(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests\nflask\n")
    ctx = {
        "target": "lab",
        "tools": [ToolInventoryEntry(name="delete_repo", description="Delete repo")],
        "requirements_path": req,
        "selected": "all",
    }
    findings = run_static_scan(ctx)
    asis = _asis(findings)
    assert "ASI02_Tool_Misuse" in asis
    assert "ASI04_Supply_Chain" in asis


def test_static_scan_asi_filter(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")
    ctx = {
        "target": "lab",
        "tools": [ToolInventoryEntry(name="delete_repo")],
        "requirements_path": req,
        "selected": "asi02",
    }
    findings = run_static_scan(ctx)
    asis = _asis(findings)
    assert "ASI02_Tool_Misuse" in asis
    assert "ASI04_Supply_Chain" not in asis


def test_asi_selector_resolves_the_published_number_not_the_module_name() -> None:
    """--asi asi04 must select supply chain, the category that number now names.

    The module names carry no number any more, so a selector matched as a
    substring of the module name would silently select nothing here.
    """
    from mas_sentry.agentic.run import _select

    available = ["tool_misuse", "supply_chain", "cascade", "action_audit"]
    assert _select("asi04", available) == ["supply_chain"]
    assert _select("asi08", available) == ["cascade"]
    assert _select("supply_chain", available) == ["supply_chain"]
    assert _select("all", available) is None


def test_static_scan_token_yields_asi03() -> None:
    now = int(time.time())
    ctx = {
        "target": "lab",
        "token": _jwt({"sub": "agent:x", "iat": now, "exp": now + 7200}),
        "selected": "all",
    }
    findings = run_static_scan(ctx)
    assert "ASI03_Identity_Abuse" in _asis(findings)


def test_static_scan_response_yields_asi09() -> None:
    ctx = {
        "target": "lab",
        "agent_response": AgentResponse(text="verified by the system"),
        "selected": "all",
    }
    findings = run_static_scan(ctx)
    assert "ASI09_Human_Agent_Trust" in _asis(findings)


def test_static_scan_empty_context_returns_empty() -> None:
    assert run_static_scan({"target": "lab", "selected": "all"}) == []


def test_static_scan_nonexistent_asi_filter_returns_empty() -> None:
    ctx = {
        "target": "lab",
        "tools": [ToolInventoryEntry(name="delete_repo")],
        "selected": "asi99",
    }
    assert run_static_scan(ctx) == []


# ─────────────── CLI ───────────────


def test_cli_agentic_scan_writes_json(tmp_path: Path) -> None:
    tools = tmp_path / "tools.json"
    tools.write_text(
        json.dumps(
            [
                {"name": "delete_repo", "description": "Delete a repository"},
                {"name": "http_post", "description": "Send HTTP"},
            ]
        )
    )
    out = tmp_path / "agentic.json"
    result = runner.invoke(
        app,
        [
            "agentic",
            "scan",
            "--target",
            "lab-router",
            "--asi",
            "all",
            "--tools-file",
            str(tools),
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert isinstance(data, list)
    asis = {t for f in data for t in f.get("tags", []) if t.startswith("ASI")}
    assert "ASI02_Tool_Misuse" in asis


def test_cli_agentic_scan_rejects_non_array_tools_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a list"}')
    out = tmp_path / "o.json"
    result = runner.invoke(
        app,
        [
            "agentic",
            "scan",
            "-t",
            "lab",
            "--tools-file",
            str(bad),
            "--out",
            str(out),
        ],
    )
    assert result.exit_code != 0
