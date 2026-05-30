# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from pathlib import Path

import pytest

from mas_sentry.protocols.mcp.runtime import _enforce_scope

# ---- _enforce_scope: the security-critical gate ---------------------------


def test_scope_allows_localhost_http():
    _enforce_scope(scheme="http", command="http://localhost:8080/mcp", confirmed=False)


def test_scope_allows_127_0_0_1():
    _enforce_scope(scheme="http", command="http://127.0.0.1:8080/", confirmed=False)


def test_scope_allows_lab_suffix():
    _enforce_scope(scheme="https", command="https://srv.lab/mcp", confirmed=False)
    _enforce_scope(scheme="http", command="http://x.test/", confirmed=False)
    _enforce_scope(scheme="https", command="https://y.local:443/", confirmed=False)


def test_scope_allows_stdio_unconditionally():
    _enforce_scope(scheme="stdio", command=["python3", "x.py"], confirmed=False)


def test_scope_rejects_public_host():
    with pytest.raises(PermissionError):
        _enforce_scope(scheme="https", command="https://api.example.com/mcp", confirmed=False)


def test_scope_confirm_overrides_rejection():
    # Explicit operator confirmation lets a public target through.
    _enforce_scope(scheme="https", command="https://api.example.com/mcp", confirmed=True)


def test_scope_rejects_lookalike_lab_suffix():
    # `evil.lab.example.com` ends with `.com`, not `.lab` — must reject.
    with pytest.raises(PermissionError):
        _enforce_scope(
            scheme="https",
            command="https://evil.lab.example.com/",
            confirmed=False,
        )


# ---- CLI _parse_target ----------------------------------------------------


def test_parse_target_stdio_splits_command():
    from mas_sentry.cli.mcp_cmd import _parse_target

    scheme, cmd = _parse_target("stdio://python3 ./server.py --root /tmp/lab")
    assert scheme == "stdio"
    assert cmd == ["python3", "./server.py", "--root", "/tmp/lab"]


def test_parse_target_http_passthrough():
    from mas_sentry.cli.mcp_cmd import _parse_target

    scheme, cmd = _parse_target("http://localhost:8080/mcp")
    assert scheme == "http"
    assert cmd == "http://localhost:8080/mcp"


def test_parse_target_rejects_unknown_scheme():
    import typer

    from mas_sentry.cli.mcp_cmd import _parse_target

    with pytest.raises(typer.BadParameter):
        _parse_target("ftp://nope")


# ---- SARIF emitter --------------------------------------------------------


def test_sarif_severity_mapping():
    from mas_sentry.reporting.sarif import severity_to_sarif_level

    assert severity_to_sarif_level("CRITICAL") == "error"
    assert severity_to_sarif_level("HIGH") == "error"
    assert severity_to_sarif_level("MEDIUM") == "warning"
    assert severity_to_sarif_level("LOW") == "note"
    assert severity_to_sarif_level("INFO") == "note"
    assert severity_to_sarif_level("WHATEVER") == "note"  # safe default


def test_sarif_document_shape():
    from mas_sentry.reporting.sarif import to_sarif

    doc = to_sarif(
        [
            {"check": "ssrf", "severity": "CRITICAL", "detail": "tool A -> imds"},
            {"check": "ssrf", "severity": "CRITICAL", "detail": "tool B -> imds"},
        ]
    )
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    # rule deduplicated by ruleId
    assert len(rules) == 1
    assert rules[0]["id"] == "MAS-SENTRY-SSRF"
    # but each finding produces a result
    assert len(doc["runs"][0]["results"]) == 2


def test_sarif_write_creates_file(tmp_path: Path):
    from mas_sentry.reporting.sarif import write_sarif

    out = tmp_path / "out" / "scan.sarif"
    write_sarif([{"check": "x", "severity": "LOW", "detail": "y"}], out)
    assert out.exists()
    parsed = json.loads(out.read_text())
    assert parsed["version"] == "2.1.0"


# ---- HTML render: autoescape (the XSS fix) --------------------------------


def test_html_report_escapes_adversarial_detail(tmp_path: Path):
    from mas_sentry.reporting.mcp_html import render_mcp_html

    out = tmp_path / "r.html"
    findings = [
        {
            "check": "tool_poisoning",
            "severity": "HIGH",
            "detail": "<script>alert('xss')</script>",
        }
    ]
    render_mcp_html("http://localhost:8080/", findings, out)
    body = out.read_text()
    # Raw <script> must NOT appear; escaped form must.
    assert "<script>alert('xss')</script>" not in body
    assert "&lt;script&gt;" in body


def test_html_report_contains_target_and_count(tmp_path: Path):
    from mas_sentry.reporting.mcp_html import render_mcp_html

    out = tmp_path / "r.html"
    render_mcp_html(
        "http://localhost/mcp",
        [{"check": "fingerprint", "severity": "INFO", "detail": "demo"}],
        out,
    )
    body = out.read_text()
    assert "http://localhost/mcp" in body
    assert "Findings:</b> 1" in body
