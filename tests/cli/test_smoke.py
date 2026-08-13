# SPDX-License-Identifier: AGPL-3.0-or-later
"""Smoke tests for every CLI command via typer.testing."""

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from mas_sentry.cli import app

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip ANSI color codes so substring assertions are terminal-agnostic.

    Rich (used by typer for --help) splits styled tokens with escape codes,
    e.g. '--verbose' renders as '-<ESC>-verbose'. On CI the runner has colors
    enabled, so raw substring checks fail. Stripping ANSI makes the help text
    match regardless of the runner's terminal detection.
    """
    return _ANSI_RE.sub("", text)


def _sample_findings_file(path: Path, *, wrapped: bool = True) -> Path:
    items = [
        {
            "module": "mcp.ssrf",
            "title": "SSRF demo",
            "detail": "fetched metadata",
            "severity": "CRITICAL",
            "target": "lab",
            "tags": ["ASI02_Tool_Misuse", "CWE-918"],
            "evidence": {"url": "http://169.254.169.254/"},
        },
        {
            "module": "agentic.supply_chain",
            "title": "Floating deps",
            "detail": "not pinned",
            "severity": "MEDIUM",
            "target": "lab",
            "tags": ["ASI04_Supply_Chain"],
        },
    ]
    payload = {"findings": items} if wrapped else items
    path.write_text(json.dumps(payload))
    return path


# ─────────────── top-level ───────────────


def test_help_lists_all_subcommands() -> None:
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0
    out = _plain(r.output)
    for cmd in ("abfp", "mcp", "agentic", "report", "doctor"):
        assert cmd in out


def test_global_flags_present() -> None:
    r = runner.invoke(app, ["--help"])
    out = _plain(r.output)
    assert "--verbose" in out
    assert "--quiet" in out
    assert "--no-color" in out


# ─────────────── doctor ───────────────


def test_doctor_runs_clean() -> None:
    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 0
    assert "Python" in r.output


# ─────────────── report convert ───────────────


def test_report_convert_to_md(tmp_path: Path) -> None:
    src = _sample_findings_file(tmp_path / "findings.json")
    out = tmp_path / "out.md"
    r = runner.invoke(
        app,
        ["report", "convert", str(src), "-f", "md", "-o", str(out), "--target", "lab"],
    )
    assert r.exit_code == 0, r.output
    assert out.exists()
    assert "SSRF demo" in out.read_text()


def test_report_convert_to_html(tmp_path: Path) -> None:
    src = _sample_findings_file(tmp_path / "f.json", wrapped=False)
    out = tmp_path / "out.html"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "html", "-o", str(out)])
    assert r.exit_code == 0
    assert "<html" in out.read_text().lower()


def test_report_convert_to_json(tmp_path: Path) -> None:
    src = _sample_findings_file(tmp_path / "f.json")
    out = tmp_path / "out.json"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "json", "-o", str(out)])
    assert r.exit_code == 0
    data = json.loads(out.read_text())
    assert data["summary"]["total"] == 2


def test_report_convert_to_junit(tmp_path: Path) -> None:
    src = _sample_findings_file(tmp_path / "f.json")
    out = tmp_path / "out.xml"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "junit", "-o", str(out)])
    assert r.exit_code == 0
    text = out.read_text()
    # one CRITICAL → one failure
    assert 'failures="1"' in text


def test_report_convert_to_sarif_carries_tags(tmp_path: Path) -> None:
    src = _sample_findings_file(tmp_path / "f.json")
    out = tmp_path / "out.sarif"
    r = runner.invoke(app, ["report", "convert", str(src), "-f", "sarif", "-o", str(out)])
    assert r.exit_code == 0
    data = json.loads(out.read_text())
    result0 = data["runs"][0]["results"][0]
    assert "CWE-918" in result0["properties"]["tags"]


def test_report_convert_unknown_format_fails(tmp_path: Path) -> None:
    src = _sample_findings_file(tmp_path / "f.json")
    r = runner.invoke(
        app,
        ["report", "convert", str(src), "-f", "pdf", "-o", str(tmp_path / "x.pdf")],
    )
    assert r.exit_code != 0


def test_report_convert_missing_source_fails(tmp_path: Path) -> None:
    r = runner.invoke(
        app,
        [
            "report",
            "convert",
            str(tmp_path / "ghost.json"),
            "-f",
            "md",
            "-o",
            str(tmp_path / "x.md"),
        ],
    )
    assert r.exit_code != 0


def test_version_flag() -> None:
    """--version prints package name + a semver-ish version and exits 0."""
    from importlib.metadata import version

    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    out = _plain(result.stdout)
    assert "mas-sentry-toolkit" in out
    assert version("mas-sentry-toolkit") in out


def test_version_short_circuits_subcommands() -> None:
    """--version is eager: it wins even with a subcommand token present."""
    result = runner.invoke(app, ["--version", "agentic"])
    assert result.exit_code == 0
    assert "mas-sentry-toolkit" in _plain(result.stdout)
