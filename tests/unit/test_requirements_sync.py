"""Guard: requirements.txt must mirror pyproject [project.dependencies].

Kills the class of bugs where requirements.txt silently drifts from the real
runtime dependency set (stale pins, phantom packages, missing deps). The file
is human-facing and consumed as a scanner input, so drift is a correctness bug,
not cosmetics.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[2]


def _normalise(spec: str) -> tuple[str, str]:
    req = Requirement(spec)
    return req.name.lower().replace("_", "-"), str(req.specifier)


def _pyproject_runtime() -> dict[str, str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return dict(_normalise(d) for d in data["project"]["dependencies"])


def _requirements_txt() -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, spec = _normalise(line)
        out[name] = spec
    return out


def test_requirements_txt_matches_pyproject() -> None:
    pyproject = _pyproject_runtime()
    reqs = _requirements_txt()
    shared = pyproject.keys() & reqs.keys()
    spec_mismatch = {k: (pyproject[k], reqs[k]) for k in shared if pyproject[k] != reqs[k]}
    assert reqs == pyproject, (
        "requirements.txt drifted from pyproject [project.dependencies]: "
        f"pyproject_only={set(pyproject) - set(reqs)}, "
        f"requirements_only={set(reqs) - set(pyproject)}, "
        f"spec_mismatch={spec_mismatch}"
    )
