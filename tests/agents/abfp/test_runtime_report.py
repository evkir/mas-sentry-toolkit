# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression: _write_report must serialise slotted BaselineStatus (no __dict__)."""

import json
from pathlib import Path

from mas_sentry.agents.abfp.baseline import BaselineStatus
from mas_sentry.agents.abfp.runtime import _write_report


def test_write_report_serializes_slotted_baseline(tmp_path: Path):
    out = tmp_path / "abfp.json"
    statuses = [
        BaselineStatus(agent_id="agent_a", observed=3, threshold=5, ready=False),
        BaselineStatus(agent_id="agent_b", observed=5, threshold=5, ready=True),
    ]
    _write_report(out, [], statuses, target="lab")
    data = json.loads(out.read_text())
    assert data["target"] == "lab"
    assert data["findings"] == []
    assert data["baseline"][0] == {"agent_id": "agent_a", "observed": 3, "threshold": 5, "ready": False}
    assert data["baseline"][1]["ready"] is True
