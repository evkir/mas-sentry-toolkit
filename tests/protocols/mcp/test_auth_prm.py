# SPDX-License-Identifier: AGPL-3.0-or-later
"""RFC 9728 discovery and what the document is allowed to say."""

from __future__ import annotations

import json
from typing import Any

from mas_sentry.protocols.mcp.audit.auth_prm import (
    FetchResult,
    HttpFetcher,
    audit_protected_resource,
    discovery_urls,
    is_loopback,
)

TARGET = "https://mcp.example.com/deep/mcp"
POINTER = "https://mcp.example.com/.well-known/oauth-protected-resource/deep/mcp"


class _Fetcher:
    """Answers from a fixed map, and records what was asked for."""

    def __init__(self, documents: dict[str, Any]) -> None:
        self.documents = documents
        self.asked: list[str] = []

    def get(self, url: str) -> FetchResult:
        self.asked.append(url)
        body = self.documents.get(url)
        if body is None:
            return FetchResult(url=url, status=404)
        text = body if isinstance(body, str) else json.dumps(body)
        return FetchResult(url=url, status=200, text=text)


def _clean_document(resource: str = TARGET) -> dict[str, Any]:
    return {
        "resource": resource,
        "authorization_servers": ["https://as.example.com"],
        "bearer_methods_supported": ["header"],
    }


def test_the_well_known_string_goes_between_the_host_and_the_path() -> None:
    """RFC 9728 Section 3: not at the root, which is the easy thing to assume."""
    urls = discovery_urls(TARGET)
    assert urls[0] == POINTER
    assert urls[-1] == "https://mcp.example.com/.well-known/oauth-protected-resource"


def test_a_resource_identifier_without_a_path_only_has_the_root_form() -> None:
    assert discovery_urls("https://mcp.example.com") == ["https://mcp.example.com/.well-known/oauth-protected-resource"]


def test_the_pointer_the_server_gave_is_tried_first() -> None:
    fetcher = _Fetcher({})
    audit_protected_resource(TARGET, "https://elsewhere.example.com/prm", fetcher, refused=True)
    assert fetcher.asked[0] == "https://elsewhere.example.com/prm"


def test_loopback_is_recognised_by_address_and_by_name() -> None:
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("127.5.5.5") is True
    assert is_loopback("::1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("mcp.example.com") is False
    assert is_loopback("10.0.0.1") is False


def test_a_conforming_document_produces_nothing() -> None:
    """A check that fires on a correct server is noise, whatever it detects."""
    fetcher = _Fetcher({POINTER: _clean_document()})
    assert audit_protected_resource(TARGET, POINTER, fetcher, refused=True) == []


def test_a_server_with_no_authentication_at_all_produces_nothing() -> None:
    """Most MCP servers have no OAuth. Reporting that is reporting the weather."""
    fetcher = _Fetcher({})
    assert audit_protected_resource(TARGET, "", fetcher, refused=False) == []


def test_a_refusal_with_no_readable_document_is_a_coverage_gap() -> None:
    fetcher = _Fetcher({})
    rows = audit_protected_resource(TARGET, POINTER, fetcher, refused=True)
    assert [r.check for r in rows] == ["auth_discovery"]
    assert rows[0].severity == "MEDIUM"
    assert "nothing behind the boundary was assessed" in rows[0].detail


def test_the_document_is_still_found_when_the_pointer_is_missing() -> None:
    """Section 5 makes WWW-Authenticate a MAY; path-based discovery still works."""
    fetcher = _Fetcher({POINTER: _clean_document()})
    assert audit_protected_resource(TARGET, "", fetcher, refused=True) == []


def test_a_body_that_is_not_json_is_not_a_document() -> None:
    fetcher = _Fetcher({POINTER: "<html>login</html>"})
    rows = audit_protected_resource(TARGET, POINTER, fetcher, refused=True)
    assert [r.check for r in rows] == ["auth_discovery"]


def test_a_document_without_the_required_resource_field_is_a_gap() -> None:
    fetcher = _Fetcher({POINTER: {"authorization_servers": ["https://as.example.com"]}})
    rows = audit_protected_resource(TARGET, POINTER, fetcher, refused=True)
    assert [r.check for r in rows] == ["auth_discovery"]
    assert "REQUIRED" in rows[0].detail


def test_a_resource_that_is_not_the_url_we_called_is_reported() -> None:
    fetcher = _Fetcher({POINTER: _clean_document(resource="https://other.example.com/mcp")})
    rows = audit_protected_resource(TARGET, POINTER, fetcher, refused=True)
    assert [r.check for r in rows] == ["auth_resource_binding"]
    assert rows[0].severity == "MEDIUM", "a reverse proxy produces this legitimately"
    assert "reverse proxy" in rows[0].detail


def test_a_trailing_slash_is_not_a_mismatch() -> None:
    """The comparison must not manufacture the finding it is looking for."""
    fetcher = _Fetcher({POINTER: _clean_document(resource=TARGET + "/")})
    assert audit_protected_resource(TARGET, POINTER, fetcher, refused=True) == []


def test_cleartext_off_loopback_is_reported() -> None:
    document = {
        "resource": TARGET,
        "authorization_servers": ["http://as.example.com"],
        "jwks_uri": "http://keys.example.com/jwks.json",
    }
    fetcher = _Fetcher({POINTER: document})
    rows = audit_protected_resource(TARGET, POINTER, fetcher, refused=True)
    assert [r.check for r in rows] == ["auth_transport"]
    assert rows[0].severity == "HIGH"
    assert "as.example.com" in rows[0].detail
    assert "keys.example.com" in rows[0].detail


def test_cleartext_to_loopback_is_not_reported() -> None:
    """Every local MCP server and every rig here runs this way."""
    local = "http://127.0.0.1:9810/mcp"
    document = {"resource": local, "authorization_servers": ["http://127.0.0.1:9810"]}
    pointer = "http://127.0.0.1:9810/.well-known/oauth-protected-resource/mcp"
    fetcher = _Fetcher({pointer: document})
    assert audit_protected_resource(local, pointer, fetcher, refused=True) == []


def test_the_query_bearer_method_is_reported() -> None:
    document = _clean_document()
    document["bearer_methods_supported"] = ["header", "query"]
    fetcher = _Fetcher({POINTER: document})
    rows = audit_protected_resource(TARGET, POINTER, fetcher, refused=True)
    assert [r.check for r in rows] == ["auth_bearer_methods"]
    assert "RFC 6750" in rows[0].detail


def test_an_issuer_outside_the_allowlist_is_refused_rather_than_fetched() -> None:
    """RFC 9728 Section 7.7, answered with the guard the product already has.

    The address in a metadata document is written by the target. Following one
    into a network this scan was not pointed at would make this tool the
    server's SSRF probe, with the operator on the receiving end - so the
    refusal is recorded and no request leaves.
    """
    fetcher = HttpFetcher()
    for url in ("http://10.0.0.1/.well-known/oauth-protected-resource", "http://as.example.com/prm"):
        result = fetcher.get(url)
        assert result.status == 0
        assert "outside the scan allowlist" in result.error


def test_the_scan_can_still_read_its_own_target(tmp_path: object) -> None:
    """Pinned in both directions: a guard that refuses everything reads nothing.

    Loopback is inside the allowlist, so the fetch is attempted and fails on
    the connection rather than on the guard.
    """
    result = HttpFetcher(timeout=1.0).get("http://127.0.0.1:1/.well-known/oauth-protected-resource")
    assert "outside the scan allowlist" not in result.error


def test_header_and_body_alone_are_not_reported() -> None:
    document = _clean_document()
    document["bearer_methods_supported"] = ["header", "body"]
    fetcher = _Fetcher({POINTER: document})
    assert audit_protected_resource(TARGET, POINTER, fetcher, refused=True) == []
