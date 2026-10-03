# SPDX-License-Identifier: AGPL-3.0-or-later
"""The basis of a correlation verdict reaches every report format, not two.

A verdict a reviewer cannot reconstruct is not deterministic (R-7.2), and until
this landed the basis travelled only inside the `detail` sentence. The row now
carries it as structured keys, which the MCP adapter turns into the unified
Finding's evidence block - and that block was rendered only by the Markdown and
JSON reports. SARIF promoted five keys the agentic modules emit and dropped the
rest; the HTML template rendered four shapes of its own and ignored anything
else. So a protocol finding arrived in the two formats an operator actually opens
with a verdict and no way to check it, which is the silent-loss class this
project treats as its worst defect (R-2.1).

Every case here drives the real pipeline - `mcp scan` into `report convert` -
rather than constructing a Finding, because the gap was never in the adapter but
in what the formatters chose to render (R-2.3).
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app
from mas_sentry.protocols.mcp import known_cves
from mas_sentry.protocols.mcp.known_cves import load_known_servers

from .test_cve_correlation import SERVER
from .test_cve_version_ranges import _TRUTHFUL

runner = CliRunner()


@pytest.fixture
def table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], None]]:
    def _write(text: str) -> None:
        path = tmp_path / "known_cves.toml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setattr(known_cves, "_TABLE", path)
        load_known_servers.cache_clear()

    yield _write
    load_known_servers.cache_clear()


@pytest.fixture
def server(tmp_path: Path) -> Path:
    path = tmp_path / "server.py"
    path.write_text(SERVER)
    return path


def _scan(server: Path, name: str, version: str, out: Path) -> None:
    target = f"stdio://{sys.executable} {server} {name} {version}".rstrip()
    result = runner.invoke(app, ["mcp", "scan", "--target", target, "--checks", "fingerprint", "-o", str(out)])
    assert result.exit_code == 0, result.output


def _convert(src: Path, out: Path, fmt: str) -> None:
    result = runner.invoke(app, ["report", "convert", str(src), "-f", fmt, "-o", str(out), "--target", "rig"])
    assert result.exit_code == 0, result.output


def _pipeline(table, server: Path, tmp_path: Path, version: str, fmt: str, source: str = _TRUTHFUL) -> Path:  # type: ignore[no-untyped-def]
    table(source)
    scan = tmp_path / "scan.json"
    _scan(server, "truthful-server", version, scan)
    out = tmp_path / f"report.{fmt}"
    _convert(scan, out, fmt)
    return out


def test_the_scan_row_carries_both_sides_of_the_comparison(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """What the server announced and the bound it was weighed against."""
    table(_TRUTHFUL)
    scan = tmp_path / "scan.json"
    _scan(server, "truthful-server", "1.0.0", scan)

    row = next(r for r in json.loads(scan.read_text(encoding="utf-8")) if r["check"] == "known_cve")
    assert row["observed_version"] == "1.0.0"
    assert row["observed_name"] == "truthful-server"
    assert row["bound"] == "< 2.0.0"
    assert row["cve"] == "CVE-2026-11111"
    assert row["source"] == "https://example.invalid/fixed"
    assert row["version_source"] == "server"


def test_the_bound_is_quoted_from_the_advisory_not_rendered_from_the_comparison(
    table, server: Path, tmp_path: Path
) -> None:  # type: ignore[no-untyped-def]
    """A windowed advisory keeps both of its ends, so the source can be checked."""
    table(_TRUTHFUL)
    scan = tmp_path / "scan.json"
    _scan(server, "truthful-server", "1.6.0", scan)

    row = next(r for r in json.loads(scan.read_text(encoding="utf-8")) if r.get("cve") == "CVE-2026-22222")
    assert row["bound"] == ">= 1.5.0 and < 1.9.0"


def test_the_evidence_block_survives_into_the_unified_finding(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    out = _pipeline(table, server, tmp_path, "1.0.0", "json")
    finding = next(f for f in json.loads(out.read_text())["findings"] if f["module"] == "mcp.known_cve")

    assert finding["evidence"]["bound"] == "< 2.0.0"
    assert finding["evidence"]["observed_version"] == "1.0.0"
    assert finding["evidence"]["source"] == "https://example.invalid/fixed"


def test_sarif_carries_the_basis_in_result_properties(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The format a triager opens, and the one that dropped everything unknown."""
    out = _pipeline(table, server, tmp_path, "1.0.0", "sarif")
    results = json.loads(out.read_text())["runs"][0]["results"]
    result = next(r for r in results if "CVE-2026-11111" in r["message"]["text"])

    evidence = result["properties"]["evidence"]
    assert evidence["bound"] == "< 2.0.0"
    assert evidence["observed_version"] == "1.0.0"
    assert evidence["source"] == "https://example.invalid/fixed"


def test_html_shows_the_basis_in_the_report_body(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    out = _pipeline(table, server, tmp_path, "1.0.0", "html")
    body = out.read_text(encoding="utf-8")

    assert "observed_version" in body
    assert "&lt; 2.0.0" in body or "< 2.0.0" in body
    assert "https://example.invalid/fixed" in body


def test_markdown_shows_the_basis_in_the_report_body(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    out = _pipeline(table, server, tmp_path, "1.0.0", "md")
    body = out.read_text(encoding="utf-8")

    assert "observed_version" in body
    assert "< 2.0.0" in body


def test_an_unresolved_row_lists_what_an_operator_has_to_settle(table, server: Path, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    """The list is structured, not only prose: it is a worklist, not a sentence."""
    table(_TRUTHFUL.replace('version_source = "server"', 'version_source = "stale"'))
    scan = tmp_path / "scan.json"
    _scan(server, "truthful-server", "1.0.0", scan)

    row = next(r for r in json.loads(scan.read_text(encoding="utf-8")) if r["check"] == "known_cve_unverified")
    assert row["version_source"] == "stale"
    assert {u["cve"] for u in row["unresolved"]} == {"CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333"}
    assert {u["severity"] for u in row["unresolved"]} == {"HIGH", "CRITICAL"}
    assert all(u["source"].startswith("https://") for u in row["unresolved"])


def test_a_finding_with_no_extra_keys_gains_no_empty_evidence_block(tmp_path: Path) -> None:
    """The catch-all must not add an empty table to every other finding."""
    src = tmp_path / "mcp.json"
    src.write_text(
        json.dumps([{"check": "tool_poisoning", "severity": "CRITICAL", "detail": "search_notes: suspicious"}]),
        encoding="utf-8",
    )
    out = tmp_path / "out.sarif"
    _convert(src, out, "sarif")
    result = json.loads(out.read_text())["runs"][0]["results"][0]

    assert "evidence" not in result.get("properties", {})
