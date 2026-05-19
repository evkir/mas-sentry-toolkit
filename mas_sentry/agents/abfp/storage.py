# SPDX-License-Identifier: AGPL-3.0-or-later
"""SQLAlchemy persistence for ABFP fingerprints. SQLite-backed by default."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class AgentFingerprint(Base):
    __tablename__ = "agent_fingerprints"
    id: Mapped[int] = mapped_column(primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(255), index=True, unique=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    timing_vector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    payload_vector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    topic_graph: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    samples: Mapped[list[FingerprintSample]] = relationship(back_populates="fingerprint")


class FingerprintSample(Base):
    __tablename__ = "fingerprint_samples"
    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint_id: Mapped[int] = mapped_column(ForeignKey("agent_fingerprints.id"))
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    anomaly_score: Mapped[float] = mapped_column(default=0.0)
    fingerprint: Mapped[AgentFingerprint] = relationship(back_populates="samples")


def open_store(path: str | Path = "~/.mas-sentry/abfp.sqlite") -> Session:
    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{p}", future=True)
    Base.metadata.create_all(engine)
    return Session(engine, future=True)


def to_json(obj: Any) -> dict[str, Any]:
    """Helper: dataclass → plain JSON-compatible dict."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return json.loads(json.dumps(asdict(obj), default=str))
    return dict(obj) if obj else {}
