# SPDX-License-Identifier: AGPL-3.0-or-later
"""DNS rebinding tester. Reports whether a localhost MCP HTTP endpoint accepts
requests with a `Host:` header pointing to an attacker-controlled domain.

We never actually rebind DNS — we send a same-origin request with a forged Host
header. If the server accepts it, the protection layer is missing.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True, slots=True)
class RebindFinding:
    target: str
    vulnerable: bool
    accepted_origin: str | None = None
    accepted_host: str | None = None


_FORGED_HOSTS = ["attacker.example", "evil.invalid", "rebinder.test"]
_FORGED_ORIGINS = ["http://attacker.example", "https://evil.invalid"]


def test_dns_rebinding(base_url: str, timeout: float = 5.0) -> RebindFinding:
    # verify=False is intentional: this probe targets localhost/lab MCP servers
    # that typically run self-signed TLS or plain HTTP. The probe is opt-in.
    with httpx.Client(timeout=timeout, verify=False) as c:  # noqa: S501  # nosec B501
        for host in _FORGED_HOSTS:
            for origin in _FORGED_ORIGINS:
                try:
                    r = c.post(
                        base_url,
                        headers={
                            "Host": host,
                            "Origin": origin,
                            "content-type": "application/json",
                        },
                        content=b'{"jsonrpc":"2.0","method":"ping","id":1}',
                    )
                except httpx.HTTPError:
                    continue
                headers_lc = {k.lower(): v for k, v in r.headers.items()}
                if r.status_code < 400 and "access-control-allow-origin" not in headers_lc:
                    # Server replied 2xx/3xx without CORS denial → DNS-rebind vector likely open.
                    return RebindFinding(
                        target=base_url,
                        vulnerable=True,
                        accepted_origin=origin,
                        accepted_host=host,
                    )
    return RebindFinding(target=base_url, vulnerable=False)
