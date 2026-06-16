# SPDX-License-Identifier: AGPL-3.0-or-later
import httpx
import pytest

from mas_sentry.core.scope import ScopeViolation
from mas_sentry.protocols.a2a.client import A2AClient


def test_real_client_blocks_public_host():
    with pytest.raises(ScopeViolation):
        A2AClient("https://api.example.com")


def test_real_client_allows_lab_host():
    A2AClient("http://127.0.0.1:8080").close()


def test_real_client_allows_confirmed():
    A2AClient("https://api.example.com", confirmed=True).close()


def test_mock_transport_bypasses_scope():
    client = A2AClient("https://api.example.com", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    client.close()
