# SPDX-License-Identifier: AGPL-3.0-or-later
"""BaselineCollector — gates ABFP fingerprint build on minimum sample size."""
from __future__ import annotations

from dataclasses import dataclass

from .observer import MessageObserver

DEFAULT_BASELINE_THRESHOLD = 500


@dataclass(frozen=True, slots=True)
class BaselineStatus:
    agent_id: str
    observed: int
    threshold: int
    ready: bool

    @property
    def progress(self) -> float:
        return min(1.0, self.observed / self.threshold)


class BaselineCollector:
    """Decides when an agent has accumulated enough data for fingerprinting."""

    def __init__(self, observer: MessageObserver, threshold: int = DEFAULT_BASELINE_THRESHOLD) -> None:
        self._obs = observer
        self._threshold = threshold

    @property
    def threshold(self) -> int:
        return self._threshold

    def status(self, agent_id: str) -> BaselineStatus:
        observed = self._obs.count_for(agent_id)
        return BaselineStatus(
            agent_id=agent_id,
            observed=observed,
            threshold=self._threshold,
            ready=observed >= self._threshold,
        )

    def all_statuses(self) -> list[BaselineStatus]:
        return [self.status(aid) for aid in self._obs.agent_ids()]

    def ready_agents(self) -> list[str]:
        return [s.agent_id for s in self.all_statuses() if s.ready]
