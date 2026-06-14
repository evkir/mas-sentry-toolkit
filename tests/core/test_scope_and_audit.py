# SPDX-License-Identifier: AGPL-3.0-or-later
import os
from pathlib import Path

import pytest

from mas_sentry.core.audit_log import tail, write
from mas_sentry.core.scope import ScopeViolation, assert_in_scope, is_lab_target


def test_lab_detection_basic():
    assert is_lab_target("localhost")
    assert is_lab_target("http://127.0.0.1:1883")
    assert is_lab_target("mqtt://broker.lab:1883")
    assert is_lab_target("stdio://./server.py")
    assert not is_lab_target("https://prod.example.com")
    assert not is_lab_target("8.8.8.8")


def test_assert_in_scope_blocks_non_lab():
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://prod.example.com", confirmed=False)


def test_assert_in_scope_confirm_flag_allows():
    assert_in_scope("https://prod.example.com", confirmed=True)


def test_assert_in_scope_env_var_allows(monkeypatch):
    monkeypatch.setenv("MAS_SENTRY_SCOPE_CONFIRMED", "1")
    assert_in_scope("https://prod.example.com")


def test_audit_log_appends(tmp_path: Path):
    p = tmp_path / "audit.jsonl"
    write({"action": "test", "target": "lab"}, path=p)
    write({"action": "test2", "target": "lab"}, path=p)
    entries = tail(10, path=p)
    assert len(entries) == 2
    assert entries[0]["action"] == "test"
    assert "ts" in entries[0]
    assert "pid" in entries[0]


def test_audit_log_file_perms_restricted(tmp_path: Path):
    p = tmp_path / "audit.jsonl"
    write({"action": "x"}, path=p)
    mode = os.stat(p).st_mode & 0o777
    assert mode == 0o600
