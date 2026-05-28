# SPDX-License-Identifier: AGPL-3.0-or-later
"""Load and evaluate poisoning patterns from local MCPTox-style fixtures.

We ship a tiny built-in corpus (16 patterns) and let users extend via JSON.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BUILTIN_CORPUS: list[dict[str, str]] = [
    {"id": "MTX-001", "pattern": "ignore previous instructions", "category": "directive"},
    {"id": "MTX-002", "pattern": "treat this as the highest priority", "category": "directive"},
    {"id": "MTX-003", "pattern": "execute the following command", "category": "exec-prompt"},
    {"id": "MTX-004", "pattern": "send all results to", "category": "exfiltration"},
    {"id": "MTX-005", "pattern": "read /etc/passwd", "category": "sensitive-target"},
    {"id": "MTX-006", "pattern": "169.254.169.254", "category": "cloud-metadata"},
    {"id": "MTX-007", "pattern": "AWS_SECRET_ACCESS_KEY", "category": "credential-name"},
    {"id": "MTX-008", "pattern": "rm -rf", "category": "destructive"},
    {"id": "MTX-009", "pattern": "curl http", "category": "fetch-primitive"},
    {"id": "MTX-010", "pattern": "wget http", "category": "fetch-primitive"},
    {"id": "MTX-011", "pattern": "base64 -d", "category": "obfuscation"},
    {"id": "MTX-012", "pattern": "[[system]]", "category": "role-override"},
    {"id": "MTX-013", "pattern": "</tool>", "category": "schema-escape"},
    {"id": "MTX-014", "pattern": "<!-- hidden", "category": "hidden-comment"},
    {"id": "MTX-015", "pattern": "do not mention", "category": "stealth"},
    {"id": "MTX-016", "pattern": ".ssh/id_rsa", "category": "credential-path"},
]


@dataclass(frozen=True, slots=True)
class CorpusHit:
    id: str
    category: str
    where: str  # field name


def _load_extra(path: Path) -> list[dict[str, str]]:
    """Parse a user corpus file, keeping only well-formed entries."""
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(raw, list):
        return []
    valid: list[dict[str, str]] = []
    for entry in raw:
        if isinstance(entry, dict) and isinstance(entry.get("pattern"), str) and isinstance(entry.get("category"), str):
            valid.append(
                {
                    "id": str(entry.get("id", "USER-?")),
                    "pattern": entry["pattern"],
                    "category": entry["category"],
                }
            )
    return valid


def evaluate_against_corpus(fields: dict[str, str], extra_corpus_path: Path | None = None) -> list[CorpusHit]:
    corpus = list(BUILTIN_CORPUS)
    if extra_corpus_path and extra_corpus_path.exists():
        corpus.extend(_load_extra(extra_corpus_path))
    hits: list[CorpusHit] = []
    for fname, text in fields.items():
        lower = (text or "").lower()
        for entry in corpus:
            if entry["pattern"].lower() in lower:
                hits.append(CorpusHit(id=entry["id"], category=entry["category"], where=fname))
    return hits
