"""Bounded cooldown suppression for stable Finding fingerprints."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable

from shared_llm_core.finding import Finding

DEFAULT_FINDING_COOLDOWN = timedelta(minutes=5)
DEFAULT_MAX_FINGERPRINTS = 10_000


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class DedupDecision:
    """One auditable accept/suppress decision."""

    accepted: bool
    reason: str
    fingerprint: str | None


class FindingDeduplicator:
    """Suppress repeated fingerprints for one bounded cooldown period."""

    def __init__(
        self,
        *,
        cooldown: timedelta = DEFAULT_FINDING_COOLDOWN,
        max_entries: int = DEFAULT_MAX_FINGERPRINTS,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if cooldown.total_seconds() <= 0:
            raise ValueError("cooldown must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.cooldown = cooldown
        self.max_entries = max_entries
        self._clock = clock
        self._accepted_at: OrderedDict[str, datetime] = OrderedDict()

    def __len__(self) -> int:
        return len(self._accepted_at)

    def accept(self, finding: Finding) -> DedupDecision:
        """Return whether a Finding should be emitted now."""
        fingerprint = finding.metadata.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            return DedupDecision(True, "missing_fingerprint", None)

        now = _utc(self._clock())
        self._prune(now)
        previous = self._accepted_at.get(fingerprint)
        if previous is not None and now - previous < self.cooldown:
            return DedupDecision(False, "cooldown", fingerprint)

        self._accepted_at[fingerprint] = now
        self._accepted_at.move_to_end(fingerprint)
        while len(self._accepted_at) > self.max_entries:
            self._accepted_at.popitem(last=False)
        return DedupDecision(True, "new_or_expired", fingerprint)

    def fingerprints(self) -> tuple[str, ...]:
        """Return retained fingerprints, newest accepted first."""
        return tuple(reversed(self._accepted_at))

    def _prune(self, now: datetime) -> None:
        cutoff = now - self.cooldown
        for fingerprint, accepted_at in tuple(self._accepted_at.items()):
            if accepted_at <= cutoff:
                del self._accepted_at[fingerprint]


__all__ = [
    "DEFAULT_FINDING_COOLDOWN",
    "DEFAULT_MAX_FINGERPRINTS",
    "DedupDecision",
    "FindingDeduplicator",
]
