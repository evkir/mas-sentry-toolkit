# SPDX-License-Identifier: AGPL-3.0-or-later
"""What CVE correlation hands an operator today, pinned against what it owes them.

`fingerprint()` correlates by name substring alone:

    suspected = [impl for impl in _KNOWN_VULN_IMPLS if impl in name_lc]

`info.version` is collected one line above and takes no part in the match, so
the verdict is a property of the server name and nothing else. Three
consequences were observed through the CLI against live servers, and each is
pinned here as a case that fails until correlation respects the version.

False positives, both HIGH:
  - a release that carries the fix is given the CVE anyway, because the version
    takes no part in the match;
  - a hardened fork is given the upstream CVE, because the match was a substring
    of the announced name, and the fork is the one case a defender has actively
    worked to escape.

Both false-positive cases were first written against `markitdown`, which was a
listed key when they landed. O-3/c2 removed that entry: the identifier it carried
had no advisory behind it in NVD or GHSA, so by R-2.13 it could not move into the
table. The cases were repointed at `mcp-git`, which remains listed, and the
assertions themselves are unchanged - a target that ceased to exist is not an
assertion that needed revising.

The false negative is the costlier half, and it is why this module exists at
all. The table is keyed on distribution names, and a server announces neither
its distribution nor, in general, its own version:

  - `mcp-server-git` announces `serverInfo.name` as `mcp-git`, so the listed key
    `mcp-server-git` is not a substring of what arrives and the vulnerable
    release is passed over in silence (verified against the published package,
    2025.7.1 and 2026.8.18 alike);
  - a server that declares no version of its own reports an empty one on the
    reference SDK 2.x line, and on the 1.x line reports the version of the SDK
    rather than its own - a string that reads like a server version and is not
    one. Correlation has no basis in either case, and R-2.1 makes that an
    undecidable row rather than silence or a HIGH.

Every case drives `mas-sentry mcp scan` rather than calling `fingerprint()`
(R-2.3), and asserts on the rows the scan writes rather than on the table or the
match: the table moves into data in O-3/c2 and the matching logic is replaced in
O-3/c3, and a case phrased against either would have to be rewritten alongside
the fix it is supposed to prove (R-2.6). "No CVE" is phrased as the absence of a
high-severity CVE row rather than the absence of a named check, so renaming the
check does not quietly satisfy it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mas_sentry.cli import app

runner = CliRunner()

# Answers initialize and tools/list over newline-delimited JSON, announcing the
# name and version it was launched with. Everything correlation is allowed to
# see about a target arrives in serverInfo, so parameterising those two fields
# is the whole rig.
SERVER = r"""
import json
import sys

NAME = sys.argv[1]
VERSION = sys.argv[2] if len(sys.argv) > 2 else ""

while True:
    line = sys.stdin.readline()
    if not line:
        break
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    if msg.get("id") is None:
        continue
    if msg.get("method") == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": NAME, "version": VERSION},
        }
    elif msg.get("method") == "tools/list":
        result = {"tools": []}
    else:
        # Refused rather than answered empty: the stateless 2026-07-28 route
        # reads an empty success as a modern server describing itself.
        sys.stdout.write(
            json.dumps({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "unknown"}}) + "\n"
        )
        sys.stdout.flush()
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}) + "\n")
    sys.stdout.flush()
"""


@pytest.fixture
def server(tmp_path: Path) -> Path:
    path = tmp_path / "server.py"
    path.write_text(SERVER)
    return path


def _scan(server: Path, name: str, version: str, out: Path) -> list[dict[str, str]]:
    target = f"stdio://{sys.executable} {server} {name} {version}".rstrip()
    result = runner.invoke(app, ["mcp", "scan", "--target", target, "--checks", "fingerprint", "-o", str(out)])
    assert result.exit_code == 0, result.output
    rows: list[dict[str, str]] = json.loads(out.read_text(encoding="utf-8"))
    return rows


def _cve_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Rows that carry a CVE verdict, by subject rather than by check name.

    The check is `known_cve` today and the correlation rewrite may name it
    otherwise; what the cases below are about is whether a CVE verdict was
    reached at all.
    """
    return [r for r in rows if "cve" in r["check"]]


def test_the_fixture_server_is_scannable(server: Path, tmp_path: Path) -> None:
    """Guards the cases below, which are xfail and would absorb a broken rig.

    A fixture that stopped answering would make every pinned case fail for the
    wrong reason and read as still-pinned rather than as broken.
    """
    rows = _scan(server, "mcp-git", "2026.8.18", tmp_path / "out.json")
    assert any(r["check"] == "fingerprint" for r in rows)


@pytest.mark.xfail(strict=True, reason="correlation ignores info.version; fixed in O-3/c3")
def test_a_patched_release_is_not_given_the_cve_it_fixed(server: Path, tmp_path: Path) -> None:
    """2026.8.18 is the current mcp-server-git; every listed CVE is fixed in it."""
    rows = _scan(server, "mcp-git", "2026.8.18", tmp_path / "out.json")
    assert not [r for r in _cve_rows(rows) if r["severity"] in ("HIGH", "CRITICAL")]


def test_a_hardened_fork_is_not_given_the_cve_of_the_name_it_contains(server: Path, tmp_path: Path) -> None:
    """The fork is the one target whose maintainer acted; it must clear."""
    rows = _scan(server, "my-hardened-mcp-git-fork", "1.0.0", tmp_path / "out.json")
    assert not [r for r in _cve_rows(rows) if r["severity"] in ("HIGH", "CRITICAL")]


def test_a_vulnerable_release_under_its_wire_name_is_not_passed_over(server: Path, tmp_path: Path) -> None:
    """`mcp-server-git` announces `mcp-git`, which is what the table is keyed on."""
    rows = _scan(server, "mcp-git", "2025.7.1", tmp_path / "out.json")
    assert _cve_rows(rows)


@pytest.mark.xfail(strict=True, reason="an unusable version yields a HIGH rather than a gap; fixed in O-3/c3")
def test_a_server_that_announces_no_version_is_reported_as_undecidable(server: Path, tmp_path: Path) -> None:
    """No version is no basis: the row has to say so instead of asserting a CVE.

    Silence would hide the target and a HIGH would invent a verdict, so the
    scan owes a row that is neither (R-2.1).
    """
    rows = _scan(server, "mcp-git", "", tmp_path / "out.json")
    cve = _cve_rows(rows)
    assert cve
    assert not [r for r in cve if r["severity"] in ("HIGH", "CRITICAL")]
