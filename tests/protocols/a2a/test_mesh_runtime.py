# SPDX-License-Identifier: AGPL-3.0-or-later
"""End-to-end tests for the A2A mesh scan orchestrator (offline via MockTransport)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from mas_sentry.core.finding import Severity
from mas_sentry.protocols.a2a.runtime import run_mesh_scan


def _card(name: str, *scopes: str) -> dict:
    flows = {"clientCredentials": {"scopes": {s: "" for s in scopes}}}
    return {
        "name": name,
        "description": "",
        "url": f"http://{name}.lab",
        "version": "1.0",
        "securitySchemes": {"oauth2": {"type": "oauth2", "flows": flows}},
    }


def _mock(cards: dict[str, dict]) -> httpx.MockTransport:
    def handler(req: httpx.Request) -> httpx.Response:
        card = cards.get(req.url.host)
        if card is None or req.url.path != "/.well-known/agent-card.json":
            return httpx.Response(404)
        return httpx.Response(200, json=card)

    return httpx.MockTransport(handler)


def _manifest(tmp_path: Path, agents: list[tuple[str, str]], edges: list[list[str]]) -> Path:
    p = tmp_path / "mesh.json"
    p.write_text(json.dumps({"agents": [{"id": i, "url": u} for i, u in agents], "edges": edges}))
    return p


def test_mesh_scan_flags_escalation(tmp_path: Path) -> None:
    cards = {"a.lab": _card("a", "read"), "b.lab": _card("b", "read", "admin")}
    manifest = _manifest(tmp_path, [("A", "http://a.lab"), ("B", "http://b.lab")], [["A", "B"]])
    out = tmp_path / "mesh-out.json"
    findings = run_mesh_scan(manifest=manifest, out=out, scope_confirmed=False, transport=_mock(cards))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity is Severity.HIGH
    assert f.module == "a2a.mesh.priv_esc"
    assert f.evidence["delegate"] == "B"
    assert f.evidence["gained_scopes"] == ["admin"]
    payload = json.loads(out.read_text())
    assert payload["summary"]["total"] == 1
    assert payload["target"].startswith("mesh:")


def test_mesh_scan_clean_mesh_no_findings(tmp_path: Path) -> None:
    cards = {"a.lab": _card("a", "read", "write"), "b.lab": _card("b", "read")}
    manifest = _manifest(tmp_path, [("A", "http://a.lab"), ("B", "http://b.lab")], [["A", "B"]])
    out = tmp_path / "mesh-out.json"
    findings = run_mesh_scan(manifest=manifest, out=out, scope_confirmed=False, transport=_mock(cards))
    assert findings == []
    assert json.loads(out.read_text())["summary"]["total"] == 0


def test_mesh_scan_transitive_critical(tmp_path: Path) -> None:
    cards = {
        "a.lab": _card("a", "read"),
        "b.lab": _card("b", "read"),
        "c.lab": _card("c", "read", "admin"),
    }
    manifest = _manifest(
        tmp_path,
        [("A", "http://a.lab"), ("B", "http://b.lab"), ("C", "http://c.lab")],
        [["A", "B"], ["B", "C"]],
    )
    out = tmp_path / "mesh-out.json"
    findings = run_mesh_scan(manifest=manifest, out=out, scope_confirmed=False, transport=_mock(cards))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["delegation_chain"] == ["A", "B", "C"]
