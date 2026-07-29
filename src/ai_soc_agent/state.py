"""Bounded in-memory event state for continuous correlation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable, Iterable

from ai_soc_agent.normalizer import NormalizedEvent, ensure_utc

DEFAULT_STATE_HORIZON = timedelta(days=1)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _event_fingerprint(event: NormalizedEvent) -> str:
    material = {
        **event.to_prompt_dict(),
        "raw": event.raw,
    }
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class StateAppendResult:
    """Counts describing one state append operation."""

    accepted: int = 0
    duplicates: int = 0
    expired: int = 0
    evicted: int = 0


@dataclass(frozen=True, slots=True)
class _StoredEvent:
    sequence: int
    fingerprint: str
    event: NormalizedEvent


class WindowStateStore:
    """Retain deduplicated events within bounded event-time windows.

    The store is intentionally unaware of rules and persistence. Callers own
    synchronization; the FastAPI server already holds one lock around state
    mutation and snapshots.
    """

    def __init__(
        self,
        *,
        max_events: int = 10_000,
        horizon: timedelta = DEFAULT_STATE_HORIZON,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if max_events <= 0:
            raise ValueError("max_events must be positive")
        if horizon.total_seconds() <= 0:
            raise ValueError("horizon must be positive")
        self.max_events = max_events
        self.horizon = horizon
        self._clock = clock
        self._events: dict[str, list[_StoredEvent]] = {}
        self._fingerprints: dict[str, set[str]] = {}
        self._watermarks: dict[str, datetime] = {}
        self._sequence = 0

    def __len__(self) -> int:
        return sum(len(events) for events in self._events.values())

    def append(
        self,
        events: Iterable[NormalizedEvent],
        *,
        namespace: str = "default",
    ) -> StateAppendResult:
        """Add events and return dedupe/expiry/capacity accounting."""
        if not namespace:
            raise ValueError("namespace must not be empty")
        incoming = list(events)
        if not incoming:
            return StateAppendResult()

        event_times = [ensure_utc(event.ts) for event in incoming]
        previous_watermark = self._watermarks.get(namespace)
        watermark = max(
            event_times
            + ([previous_watermark] if previous_watermark is not None else [])
        )
        cutoff = watermark - self.horizon

        bucket = self._events.setdefault(namespace, [])
        fingerprints = self._fingerprints.setdefault(namespace, set())
        accepted = duplicates = expired = 0
        for event, event_time in zip(incoming, event_times):
            if event_time < cutoff:
                expired += 1
                continue
            fingerprint = _event_fingerprint(event)
            if fingerprint in fingerprints:
                duplicates += 1
                continue
            self._sequence += 1
            bucket.append(
                _StoredEvent(
                    sequence=self._sequence,
                    fingerprint=fingerprint,
                    event=event,
                )
            )
            fingerprints.add(fingerprint)
            accepted += 1

        self._watermarks[namespace] = watermark
        bucket.sort(key=lambda item: (item.event.ts, item.sequence))
        evicted = self._prune_namespace(namespace, cutoff)
        evicted += self._enforce_capacity()
        self._drop_empty_namespaces()
        return StateAppendResult(
            accepted=accepted,
            duplicates=duplicates,
            expired=expired,
            evicted=evicted,
        )

    def snapshot(
        self,
        namespace: str = "default",
        *,
        limit: int | None = None,
    ) -> list[NormalizedEvent]:
        """Return an event-time-ordered copy for one namespace."""
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive")
        stored = self._events.get(namespace, ())
        selected = stored[-limit:] if limit is not None else stored
        return [item.event for item in selected]

    def namespaces(self) -> tuple[str, ...]:
        """Return non-empty namespaces in deterministic order."""
        return tuple(sorted(self._events))

    def prune_expired(self, reference: datetime | None = None) -> int:
        """Drop history older than ``reference`` (or the injected clock)."""
        current = ensure_utc(reference if reference is not None else self._clock())
        cutoff = current - self.horizon
        evicted = sum(
            self._prune_namespace(namespace, cutoff)
            for namespace in tuple(self._events)
        )
        self._drop_empty_namespaces()
        return evicted

    def _prune_namespace(self, namespace: str, cutoff: datetime) -> int:
        bucket = self._events.get(namespace, [])
        index = 0
        while index < len(bucket) and bucket[index].event.ts < cutoff:
            index += 1
        if index == 0:
            return 0
        removed = bucket[:index]
        del bucket[:index]
        fingerprints = self._fingerprints[namespace]
        for item in removed:
            fingerprints.discard(item.fingerprint)
        return len(removed)

    def _enforce_capacity(self) -> int:
        evicted = 0
        while len(self) > self.max_events:
            namespace, item = min(
                (
                    (namespace, bucket[0])
                    for namespace, bucket in self._events.items()
                    if bucket
                ),
                key=lambda pair: (pair[1].event.ts, pair[1].sequence),
            )
            self._events[namespace].pop(0)
            self._fingerprints[namespace].discard(item.fingerprint)
            evicted += 1
        return evicted

    def _drop_empty_namespaces(self) -> None:
        for namespace in tuple(self._events):
            if self._events[namespace]:
                continue
            del self._events[namespace]
            self._fingerprints.pop(namespace, None)
            self._watermarks.pop(namespace, None)


__all__ = [
    "DEFAULT_STATE_HORIZON",
    "StateAppendResult",
    "WindowStateStore",
]
