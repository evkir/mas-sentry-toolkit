# SPDX-License-Identifier: AGPL-3.0-or-later
"""A target that cannot be reached still produces a report.

Every other outcome of `mcp scan` reaches a file. An unreachable one used to
reach nothing: the process died on the exception before `out.write_text`, so a
pipeline that pipes a scan into `report convert` broke on a missing file, and
the break looked identical whether the target was down or this scanner had
crashed. `mqtt scan` and `amqp scan` had answered with a gap finding all along.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from mas_sentry.protocols.mcp.runtime import run_mcp_scan


def _closed_port() -> int:
    """A port nothing is listening on, taken and released so it stays free."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _scan(tmp_path: Path, scheme: str, command: str | list[str], name: str) -> list[dict[str, object]]:
    return run_mcp_scan(
        scheme=scheme,
        command=command,
        target_label=str(command),
        checks="all",
        out=tmp_path / f"{name}.json",
        scope_confirmed=False,
        budget_seconds=30.0,
    )


def _only_row(rows: list[dict[str, object]]) -> dict[str, object]:
    assert len(rows) == 1, f"expected one gap row, got {[r['check'] for r in rows]}"
    return rows[0]


def test_a_refused_connection_is_reported_not_raised(tmp_path: Path) -> None:
    url = f"http://127.0.0.1:{_closed_port()}/mcp"
    row = _only_row(_scan(tmp_path, "http", url, "refused"))
    assert row["check"] == "target_unreachable"
    assert row["severity"] == "MEDIUM"
    assert "refused" in str(row["detail"]).lower()
    assert "not a clean result" in str(row["detail"])


def test_a_command_that_is_not_there_is_reported_not_raised(tmp_path: Path) -> None:
    """The OSError path: nothing was spawned, so nothing could be asked."""
    row = _only_row(_scan(tmp_path, "stdio", ["mas-sentry-no-such-binary"], "missing"))
    assert row["check"] == "target_unreachable"
    assert "No such file" in str(row["detail"])


def test_a_process_that_exits_during_the_handshake_is_reported(tmp_path: Path) -> None:
    """The handshake path: something ran, and stopped before saying anything."""
    row = _only_row(_scan(tmp_path, "stdio", ["false"], "exited"))
    assert row["check"] == "target_unreachable"
    assert "initialize" in str(row["detail"])


def test_the_gap_reaches_the_file_and_not_only_the_return_value(tmp_path: Path) -> None:
    url = f"http://127.0.0.1:{_closed_port()}/mcp"
    _scan(tmp_path, "http", url, "written")
    written = json.loads((tmp_path / "written.json").read_text())
    assert [r["check"] for r in written] == ["target_unreachable"]


def test_a_defect_inside_a_check_is_not_reported_as_an_unreachable_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard is narrow on purpose.

    Catching everything would file this scanner's own faults against whatever
    it was pointed at, which is the misattribution the row exists to prevent.
    """
    from mas_sentry.protocols.mcp import runtime as runtime_mod

    def explode(*args: object, **kwargs: object) -> None:
        raise ZeroDivisionError("a defect of ours")

    monkeypatch.setattr(runtime_mod, "_run_all_checks", explode)
    with pytest.raises(ZeroDivisionError):
        _scan(tmp_path, "stdio", ["cat"], "defect")
