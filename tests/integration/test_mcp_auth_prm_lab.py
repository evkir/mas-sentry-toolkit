# SPDX-License-Identifier: AGPL-3.0-or-later
"""The RFC 9728 chain, against the SDK's own route builders.

The unit suite drives the audit from a dictionary, which agrees with whatever
its author believed the document looks like. Here the document is mounted by
`mcp.server.auth.routes`, the mount path is computed by the SDK, and the
challenge is the one the rig sends - so a divergence between MST and a
conforming server fails a test rather than passing quietly.

Driven over ASGI rather than a socket. The rig is the same module either way,
and an in-process app has no port to collide with and no process to outlive
the test.
"""

from __future__ import annotations

import asyncio
import importlib
import os
from typing import Any

import pytest

pytest.importorskip("mcp", reason="mcp SDK not installed - pip install -e '.[lab]'")
pytest.importorskip("starlette")

import httpx

from mas_sentry.protocols.mcp.audit.auth_prm import (
    FetchResult,
    audit_protected_resource,
    discovery_urls,
)

BASE = "http://127.0.0.1:9810"
TARGET = f"{BASE}/mcp"


async def _collect(mode: str) -> tuple[int, str, dict[str, tuple[int, str]]]:
    """Ask the rig everything the audit would ask it, in one pass."""
    os.environ["MAS_SENTRY_AUTH_BREAK"] = mode
    os.environ["MAS_SENTRY_AUTH_PORT"] = "9810"
    rig = importlib.import_module("lab.mcp.auth_server")
    importlib.reload(rig)

    transport = httpx.ASGITransport(app=rig.build_app())
    async with httpx.AsyncClient(transport=transport, base_url=BASE) as client:
        refusal = await client.post("/mcp", json={})
        header = refusal.headers.get("www-authenticate", "")
        pointer = ""
        if 'resource_metadata="' in header:
            pointer = header.split('resource_metadata="', 1)[1].split('"', 1)[0]
        answers: dict[str, tuple[int, str]] = {}
        for url in discovery_urls(TARGET, pointer):
            got = await client.get(url.replace(BASE, ""))
            answers[url] = (got.status_code, got.text)
        return refusal.status_code, pointer, answers


def _audit(mode: str) -> list[Any]:
    status, pointer, answers = asyncio.run(_collect(mode))

    class _Replay:
        def get(self, url: str) -> FetchResult:
            code, text = answers.get(url, (0, ""))
            return FetchResult(url=url, status=code, text=text, error="" if code else "not fetched")

    return audit_protected_resource(TARGET, pointer, _Replay(), refused=status == 401)


@pytest.fixture(autouse=True)
def _restore_break_mode():
    previous = os.environ.get("MAS_SENTRY_AUTH_BREAK")
    yield
    os.environ["MAS_SENTRY_AUTH_BREAK"] = previous or ""
    importlib.reload(importlib.import_module("lab.mcp.auth_server"))


def test_the_pointer_the_sdk_builds_is_the_path_based_url() -> None:
    """The fact the whole chain rests on: the well-known string is not at the root."""
    _, pointer, _ = asyncio.run(_collect(""))
    assert pointer == f"{BASE}/.well-known/oauth-protected-resource/mcp"


def test_a_conforming_server_produces_no_rows() -> None:
    assert _audit("") == []


def test_an_unmounted_document_is_a_coverage_gap() -> None:
    rows = _audit("prm")
    assert [r.check for r in rows] == ["auth_discovery"]


def test_a_missing_challenge_does_not_hide_the_document() -> None:
    """Without the pointer the audit must still find it by path, and stay quiet."""
    assert _audit("challenge") == []


def test_a_document_that_says_the_wrong_things_is_reported() -> None:
    rows = _audit("weak")
    found = {r.check: r for r in rows}
    assert set(found) == {"auth_resource_binding", "auth_transport", "auth_bearer_methods"}
    assert found["auth_transport"].severity == "HIGH"
    assert found["auth_resource_binding"].severity == "MEDIUM"
