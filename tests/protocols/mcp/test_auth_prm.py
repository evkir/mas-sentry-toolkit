# SPDX-License-Identifier: AGPL-3.0-or-later
"""RFC 9728 discovery and what the document is allowed to say."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from mas_sentry.protocols.mcp.audit.auth_prm import (
    MAX_DOCUMENT_CHARS,
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
    """On the target's own origin, the pointer is what the server asked us to use."""
    fetcher = _Fetcher({})
    audit_protected_resource(TARGET, POINTER, fetcher, refused=True)
    assert fetcher.asked[0] == POINTER


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


class _CountingBudget:
    """Answers spend() from a fixed script and records what was asked for."""

    def __init__(self, allow: int) -> None:
        self.allow = allow
        self.spent: list[str] = []

    def spend(self, method: str) -> bool:
        self.spent.append(method)
        if self.allow <= 0:
            return False
        self.allow -= 1
        return True


class _SlowHandler(BaseHTTPRequestHandler):
    """Writes a body slowly and forever, the way a target that wants our time does.

    Each read lands well inside any sane httpx timeout, which is exactly why
    the timeout does not bound this: it measures the gap between reads, not the
    length of the request.
    """

    chunk = b"x" * 4096
    pause = 0.05
    chunks = 10_000
    hits = 0

    def do_GET(self) -> None:
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        try:
            for _ in range(self.chunks):
                time.sleep(self.pause)
                self.wfile.write(b"%X\r\n" % len(self.chunk) + self.chunk + b"\r\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ValueError):
            return

    def log_message(self, *args: Any) -> None:
        return


class _FloodHandler(_SlowHandler):
    """The same, without the pauses: a body far larger than the cap."""

    chunk = b"y" * (64 * 1024)
    pause = 0.0
    chunks = 64


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/.well-known/oauth-protected-resource"


def test_the_deadline_bounds_a_request_the_timeout_does_not() -> None:
    """The transport learned this on Day 85; the metadata fetcher had not.

    httpx applies its timeout between reads, so a server writing a chunk every
    50ms keeps every read inside a two second timeout and holds the request as
    long as it likes. Only a wall clock catches it.
    """
    server, url = _serve(_SlowHandler)
    try:
        started = time.monotonic()
        result = HttpFetcher(timeout=2.0, deadline=1.0).get(url)
        elapsed = time.monotonic() - started
    finally:
        server.shutdown()
    assert elapsed < 5.0, f"the fetch ran for {elapsed:.1f}s under a 1.0s deadline"
    assert result.bounded
    assert "scanner bound" in result.error
    assert not result.ok


def test_the_cap_stops_the_read_rather_than_slicing_what_was_read() -> None:
    """The bound has to be applied on the wire, not to the finished string.

    A cap that slices `response.text` is a measurement taken after the whole
    body has been pulled into memory, which is not a cap on anything.
    """
    server, url = _serve(_FloodHandler)
    try:
        result = HttpFetcher(timeout=5.0, deadline=10.0).get(url)
    finally:
        server.shutdown()
    assert len(result.text) == MAX_DOCUMENT_CHARS
    assert result.bounded
    assert not result.ok


def test_a_spent_budget_stops_the_fetch_before_the_socket() -> None:
    """These requests cost the operator time like every other request does."""
    budget = _CountingBudget(allow=0)
    _SlowHandler.hits = 0
    server, url = _serve(_SlowHandler)
    try:
        result = HttpFetcher(timeout=1.0, deadline=1.0, budget=budget).get(url)
    finally:
        server.shutdown()
    assert _SlowHandler.hits == 0, "the request went out after the budget was gone"
    assert result.bounded
    assert "scan budget" in result.error
    assert budget.spent == [f"GET {url}"]


def test_a_fetch_that_succeeds_still_spends_the_budget() -> None:
    """Pinned in both directions: a budget nothing draws from bounds nothing."""
    budget = _CountingBudget(allow=3)
    result = HttpFetcher(timeout=1.0, deadline=1.0, budget=budget).get(
        "http://127.0.0.1:1/.well-known/oauth-protected-resource"
    )
    assert budget.spent, "a request left without being counted"
    assert not result.bounded, "a connection failure is the target's, not a bound of ours"


class _BoundedFetcher:
    """Every attempt cut short by this scanner rather than by the target."""

    def get(self, url: str) -> FetchResult:
        return FetchResult(url=url, status=200, error="stopped reading; this is a scanner bound", bounded=True)


def test_a_read_we_cut_short_is_not_reported_as_a_server_that_published_nothing() -> None:
    """Our surrender, filed as the target's defect, is a finding we invented."""
    rows = audit_protected_resource(TARGET, POINTER, _BoundedFetcher(), refused=True)
    assert [r.check for r in rows] == ["auth_discovery_bounded"]
    assert "bounds of this scanner" in rows[0].detail


def test_a_bounded_read_is_reported_even_when_the_server_never_refused() -> None:
    """No 401 does not mean no document; it means we did not finish looking."""
    rows = audit_protected_resource(TARGET, POINTER, _BoundedFetcher(), refused=False)
    assert [r.check for r in rows] == ["auth_discovery_bounded"]


def test_an_off_origin_pointer_is_recorded_and_not_requested() -> None:
    """The address is the target's to write, so following it is ours to refuse.

    Legitimate - RFC 9728 sets no origin restriction and hosting platforms that
    cannot serve /.well-known/* at the root depend on it - so it is reported at
    INFO and discovery carries on at the target's own well-known locations.
    """
    fetcher = _Fetcher({})
    rows = audit_protected_resource(TARGET, "https://elsewhere.example.com/prm", fetcher, refused=True)
    assert "https://elsewhere.example.com/prm" not in fetcher.asked
    assert fetcher.asked == discovery_urls(TARGET)
    assert rows[0].check == "auth_discovery_offhost"
    assert rows[0].severity == "INFO"
    assert [r.check for r in rows] == ["auth_discovery_offhost", "auth_discovery"]


def test_the_off_origin_row_survives_a_document_found_on_the_target() -> None:
    """Reading a document elsewhere does not make the unread one disappear."""
    document = _clean_document()
    fetcher = _Fetcher({discovery_urls(TARGET)[0]: document})
    rows = audit_protected_resource(TARGET, "https://elsewhere.example.com/prm", fetcher, refused=True)
    assert [r.check for r in rows] == ["auth_discovery_offhost"]


def test_a_pointer_differing_only_in_port_is_off_origin() -> None:
    """A different port is a different service on a host we were pointed at."""
    target = "http://127.0.0.1:9810/mcp"
    fetcher = _Fetcher({})
    rows = audit_protected_resource(target, "http://127.0.0.1:9999/prm", fetcher, refused=True)
    assert "http://127.0.0.1:9999/prm" not in fetcher.asked
    assert rows[0].check == "auth_discovery_offhost"


def test_a_confirmed_scope_does_not_open_the_pointer_to_any_address() -> None:
    """The case the scope guard cannot cover, driven the way a real scan runs.

    Every scan of a real server passes --confirm-scope, which makes the guard
    return for any host at all. The unit test that pinned this used the default
    HttpFetcher() - a configuration a real scan never has - so it stayed green
    while the property it describes did not hold. Here the fetcher is built the
    way the runtime builds it, and the refusal to follow has to come from the
    origin policy.
    """
    listener, url = _serve(_SlowHandler)
    _SlowHandler.hits = 0
    try:
        target = f"http://127.0.0.1:{listener.server_address[1] + 1}/mcp"
        fetcher = HttpFetcher(timeout=1.0, deadline=1.0, scope_confirmed=True)
        audit_protected_resource(target, url, fetcher, refused=True)
    finally:
        listener.shutdown()
    assert _SlowHandler.hits == 0, "the scan fetched an address the target chose for it"
