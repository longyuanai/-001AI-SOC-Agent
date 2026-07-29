"""Bounded human feedback records with no online rule mutation."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from threading import RLock
from typing import Callable


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class FeedbackLabel(str, Enum):
    """Allowed analyst dispositions."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


@dataclass(frozen=True, slots=True)
class FeedbackRecord:
    """One immutable analyst annotation."""

    id: str
    finding_id: str
    label: FeedbackLabel
    analyst: str
    note: str
    ts: datetime

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "label": self.label.value,
            "analyst": self.analyst,
            "note": self.note,
            "ts": self.ts.isoformat(),
        }


class FeedbackStore:
    """Thread-safe bounded storage for offline evaluation labels."""

    def __init__(
        self,
        *,
        max_records: int = 5_000,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if max_records <= 0:
            raise ValueError("max_records must be positive")
        self.max_records = max_records
        self._clock = clock
        self._records: list[FeedbackRecord] = []
        self._lock = RLock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)

    def add(
        self,
        finding_id: str,
        label: FeedbackLabel | str,
        analyst: str,
        note: str = "",
    ) -> FeedbackRecord:
        """Append one record; this method has no reference to RuleEngine."""
        normalized_finding_id = finding_id.strip()
        normalized_analyst = analyst.strip()
        if not normalized_finding_id:
            raise ValueError("finding_id must not be empty")
        if not normalized_analyst:
            raise ValueError("analyst must not be empty")
        normalized_label = (
            label if isinstance(label, FeedbackLabel) else FeedbackLabel(label)
        )
        record = FeedbackRecord(
            id=str(uuid.uuid4()),
            finding_id=normalized_finding_id,
            label=normalized_label,
            analyst=normalized_analyst,
            note=note.strip(),
            ts=_utc(self._clock()),
        )
        with self._lock:
            self._records.append(record)
            if len(self._records) > self.max_records:
                del self._records[: len(self._records) - self.max_records]
        return record

    def query(
        self,
        *,
        finding_id: str | None = None,
        label: FeedbackLabel | str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[FeedbackRecord]:
        """Return matching records newest-first."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        if offset < 0:
            raise ValueError("offset must not be negative")
        normalized_label = (
            label
            if label is None or isinstance(label, FeedbackLabel)
            else FeedbackLabel(label)
        )
        with self._lock:
            records = self._matching(finding_id, normalized_label)
        return records[offset : offset + limit]

    def count(
        self,
        *,
        finding_id: str | None = None,
        label: FeedbackLabel | str | None = None,
    ) -> int:
        """Count records matching optional filters."""
        normalized_label = (
            label
            if label is None or isinstance(label, FeedbackLabel)
            else FeedbackLabel(label)
        )
        with self._lock:
            return len(self._matching(finding_id, normalized_label))

    def summary(self) -> dict[str, int]:
        """Return global label counts for offline rule evaluation."""
        counts = {label.value: 0 for label in FeedbackLabel}
        with self._lock:
            for record in self._records:
                counts[record.label.value] += 1
        return counts

    def _matching(
        self,
        finding_id: str | None,
        label: FeedbackLabel | None,
    ) -> list[FeedbackRecord]:
        return [
            record
            for record in reversed(self._records)
            if (finding_id is None or record.finding_id == finding_id)
            and (label is None or record.label is label)
        ]


__all__ = [
    "FeedbackLabel",
    "FeedbackRecord",
    "FeedbackStore",
]
