# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end tests for the static agentic scan and its CLI wiring."""

import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest
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
    findings = run_static_scan(ctx).findings
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
    findings = run_static_scan(ctx).findings
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
    findings = run_static_scan(ctx).findings
    assert "ASI03_Identity_Abuse" in _asis(findings)


def test_static_scan_response_yields_asi09() -> None:
    ctx = {
        "target": "lab",
        "agent_response": AgentResponse(text="verified by the system"),
        "selected": "all",
    }
    findings = run_static_scan(ctx).findings
    assert "ASI09_Human_Agent_Trust" in _asis(findings)


def test_static_scan_empty_context_runs_nothing() -> None:
    run = run_static_scan({"target": "lab", "selected": "all"})
    assert run.findings == []
    assert run.modules_ran == []


def test_static_scan_nonexistent_asi_filter_runs_nothing() -> None:
    ctx = {
        "target": "lab",
        "tools": [ToolInventoryEntry(name="delete_repo")],
        "selected": "asi99",
    }
    run = run_static_scan(ctx)
    assert run.findings == []
    assert run.modules_ran == []


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


# --------------- coverage is not cleanliness ---------------


def _seen(result: Any) -> str:
    """Everything the caller saw, whichever stream the runner kept it on."""
    text = result.output
    try:
        return text + result.stderr
    except (AttributeError, ValueError):  # pragma: no cover - runner version
        return text


def test_static_scan_reports_which_modules_ran(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")
    run = run_static_scan({"target": "lab", "requirements_path": req, "selected": "all"})
    assert run.modules_ran == ["supply_chain"]


def test_no_coverage_reason_separates_an_unfed_module_from_an_unknown_one() -> None:
    from mas_sentry.agentic.run import no_coverage_reason

    unfed = no_coverage_reason("asi04")
    assert "supply_chain" in unfed
    assert "--requirements" in unfed

    unfeedable = no_coverage_reason("asi08")
    assert "cascade" in unfeedable
    assert "cannot supply" in unfeedable

    unknown = no_coverage_reason("asi99")
    assert "matches no module" in unknown

    nothing_given = no_coverage_reason("all")
    assert "--requirements" in nothing_given


@pytest.mark.parametrize("selector", [f"asi{n:02d}" for n in range(1, 11)])
def test_cli_runs_the_fed_category_and_refuses_the_rest(selector: str, tmp_path: Path) -> None:
    """Every published number either scans something or fails loudly.

    Before this, nine of the ten wrote an empty report and exited 0, which is
    what let the dogfood job gate on a category the scan could not cover and
    stay green for six weeks.
    """
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")
    out = tmp_path / f"{selector}.json"
    result = runner.invoke(
        app,
        ["agentic", "scan", "-t", "lab", "--asi", selector, "--requirements", str(req), "--out", str(out)],
    )
    if selector == "asi04":
        assert result.exit_code == 0
        assert out.exists()
        return
    assert result.exit_code == 2, f"{selector} reported a clean scan it never ran"
    assert not out.exists(), "a scan that checked nothing must not leave a report behind"
    assert "no check ran" in _seen(result)


# --------------- a crash is not cleanliness ---------------


def _explode(*_a: object, **_k: object) -> list:
    raise RuntimeError("lockfile parser exploded")


def test_cli_exits_two_when_a_module_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A detector that died leaves no report behind and names itself."""
    from mas_sentry.agentic import supply_chain

    monkeypatch.setattr(supply_chain, "audit_supply_chain", _explode)
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")
    out = tmp_path / "o.json"
    result = runner.invoke(
        app,
        ["agentic", "scan", "-t", "lab", "--asi", "supply_chain", "--requirements", str(req), "--out", str(out)],
    )
    assert result.exit_code == 2
    assert not out.exists(), "a scan that did not finish must not leave a report behind"
    seen = _seen(result)
    assert "supply_chain" in seen
    assert "lockfile parser exploded" in seen


def test_cli_does_not_blame_missing_input_for_a_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The only selected module raised, so modules_ran is empty either way.

    Calling that a coverage gap would tell the operator to pass --requirements
    they did pass, and hide the exception that is the real fault.
    """
    from mas_sentry.agentic import supply_chain

    monkeypatch.setattr(supply_chain, "audit_supply_chain", _explode)
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")
    out = tmp_path / "o.json"
    result = runner.invoke(
        app,
        ["agentic", "scan", "-t", "lab", "--asi", "supply_chain", "--requirements", str(req), "--out", str(out)],
    )
    assert result.exit_code == 2
    seen = _seen(result)
    assert "no check ran" not in seen
    assert "scan incomplete" in seen


def test_cli_withholds_the_report_when_one_of_two_modules_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A half-finished report is byte-identical to a complete one."""
    from mas_sentry.agentic import supply_chain

    monkeypatch.setattr(supply_chain, "audit_supply_chain", _explode)
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")
    tools = tmp_path / "tools.json"
    tools.write_text(json.dumps([{"name": "run_shell", "description": "Run a shell command"}]))
    out = tmp_path / "o.json"
    result = runner.invoke(
        app,
        [
            "agentic",
            "scan",
            "-t",
            "lab",
            "--asi",
            "all",
            "--requirements",
            str(req),
            "--tools-file",
            str(tools),
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 2
    assert not out.exists()
    seen = _seen(result)
    assert "1 of 2" in seen, "the count has to say how much of the scan was lost"


def test_cli_exits_two_when_no_input_was_given(tmp_path: Path) -> None:
    out = tmp_path / "o.json"
    result = runner.invoke(app, ["agentic", "scan", "-t", "lab", "--out", str(out)])
    assert result.exit_code == 2
    assert not out.exists()


def test_cli_rejects_a_requirements_path_that_does_not_exist(tmp_path: Path) -> None:
    out = tmp_path / "o.json"
    result = runner.invoke(
        app,
        ["agentic", "scan", "-t", "lab", "--requirements", str(tmp_path / "nope.txt"), "--out", str(out)],
    )
    assert result.exit_code == 2
    assert not out.exists()


def test_cli_rejects_a_tools_file_that_does_not_exist(tmp_path: Path) -> None:
    out = tmp_path / "o.json"
    result = runner.invoke(
        app,
        ["agentic", "scan", "-t", "lab", "--tools-file", str(tmp_path / "nope.json"), "--out", str(out)],
    )
    assert result.exit_code == 2
    assert not out.exists()
