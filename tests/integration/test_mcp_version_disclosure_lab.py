# SPDX-License-Identifier: AGPL-3.0-or-later
"""What the reference SDK puts in serverInfo.version when the server names none.

O-3 correlates CVEs by version range, which presumes the version observed on the
wire belongs to the server. For a large class of real targets it does not, and
this module pins the half of that fact the CI lab can reproduce.

On the reference SDK 2.x line a server constructed without a version announces
an empty one, so the scan has no basis for a range comparison and owes an
undecidable row rather than a verdict either way.

The 1.x line is worse and is not reproducible here. `Server.create_initialization_options`
falls back to `server_version=self.version if self.version else pkg_version("mcp")`,
so a server that names no version announces the version of the SDK: the published
`mcp-server-git` 2026.8.18 scans as `mcp-git 1.30.0`, where 1.30.0 is the `mcp`
distribution and 2026.8.18 - the only version a CVE range could be about - never
reaches the wire at all. That package pins `mcp<2`, so installing it next to the
`mcp>=2.0` this lab needs would downgrade the SDK and silently skip every 2.x
case in the suite; the fact is recorded in MST_STANDOFF-PLAN.md instead of being
bought at that price.

Not an xfail: these assert what the SDK does, not what MST owes. The module
exists so that an upstream change to version disclosure breaks a test here
rather than quietly invalidating the correlation table.

Skipped when the optional lab dependencies are absent (pip install -e .[lab]).
"""

from __future__ import annotations

import json
import sys
from importlib import metadata
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app

pytest.importorskip("mcp", reason="mcp SDK not installed - pip install -e '.[lab]'")
pytest.importorskip("mcp.server.mcpserver", reason="version fallback differs on mcp 1.x - pip install -e '.[lab]'")

runner = CliRunner()

# Constructed without `version=`, which is the whole point: a server that names
# its own version is not the case correlation gets wrong.
SERVER = """
from mcp.server.mcpserver import MCPServer

srv = MCPServer(name="version-silent-server")


@srv.tool()
def ping() -> str:
    \"\"\"Answer so the scan has an inventory to enumerate.\"\"\"
    return "pong"


srv.run(transport="stdio")
"""


def _fingerprint_detail(server: Path, out: Path) -> str:
    target = f"stdio://{sys.executable} {server}"
    result = runner.invoke(app, ["mcp", "scan", "--target", target, "--checks", "fingerprint", "-o", str(out)])
    assert result.exit_code == 0, result.output
    rows: list[dict[str, str]] = json.loads(out.read_text(encoding="utf-8"))
    return next(r["detail"] for r in rows if r["check"] == "fingerprint")


def test_a_server_that_names_no_version_announces_an_empty_one(tmp_path: Path) -> None:
    """Observed through the CLI against a server built on the reference SDK."""
    server = tmp_path / "server.py"
    server.write_text(SERVER, encoding="utf-8")

    detail = _fingerprint_detail(server, tmp_path / "out.json")

    assert detail.startswith("version-silent-server")
    assert metadata.version("mcp") not in detail
