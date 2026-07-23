"""Deterministic, in-memory correlation rules for normalized events."""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ai_soc_agent.normalizer import NormalizedEvent


@dataclass(frozen=True)
class Alert:
    """One alert emitted by a correlation rule."""

    id: str
    kind: str
    severity: str
    actor: str
    targets: tuple[str, ...]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    sources: tuple[str, ...]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        """Return the stable JSON shape exposed by the API."""
        return {
            "id": self.id,
            "type": self.kind,
            "severity": self.severity,
            "actor": self.actor,
            "targets": list(self.targets),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "event_count": self.event_count,
            "sources": list(self.sources),
            "summary": self.summary,
        }


def _utc_timestamp(value: datetime) -> float:
    """Convert mixed naive/aware datetimes to a deterministic UTC timestamp."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).timestamp()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _alert_id(
    kind: str,
    actor: str,
    first_seen: datetime,
    last_seen: datetime,
    sources: tuple[str, ...],
) -> str:
    material = "|".join(
        (
            kind,
            actor,
            str(_utc_timestamp(first_seen)),
            str(_utc_timestamp(last_seen)),
            ",".join(sources),
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{kind}-{digest}"


def _build_alert(
    *,
    kind: str,
    severity: str,
    actor: str,
    events: tuple[NormalizedEvent, ...],
    summary: str,
) -> Alert:
    sources = tuple(sorted({event.source for event in events}))
    targets = tuple(
        sorted({event.target for event in events if event.target not in ("", "-", "unknown")})
    )
    first_seen = events[0].ts
    last_seen = events[-1].ts
    return Alert(
        id=_alert_id(kind, actor, first_seen, last_seen, sources),
        kind=kind,
        severity=severity,
        actor=actor,
        targets=targets,
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=len(events),
        sources=sources,
        summary=summary,
    )


def detect_brute_force(
    events: list[NormalizedEvent],
    *,
    window: timedelta = timedelta(minutes=5),
    threshold: int = 10,
) -> list[Alert]:
    """Detect an IP producing at least ``threshold`` failures in one time window."""
    if window.total_seconds() <= 0:
        raise ValueError("window must be positive")
    if threshold <= 0:
        raise ValueError("threshold must be positive")

    failures = sorted(
        (
            (_utc_timestamp(event.ts), event)
            for event in events
            if event.result == "failure" and _is_ip(event.actor)
        ),
        key=lambda item: item[0],
    )
    windows: dict[str, deque[tuple[float, NormalizedEvent]]] = defaultdict(deque)
    active_actors: set[str] = set()
    alerts: list[Alert] = []
    window_seconds = window.total_seconds()

    for timestamp, event in failures:
        actor_window = windows[event.actor]
        while actor_window and timestamp - actor_window[0][0] > window_seconds:
            actor_window.popleft()
        if len(actor_window) < threshold:
            active_actors.discard(event.actor)

        actor_window.append((timestamp, event))
        if len(actor_window) < threshold or event.actor in active_actors:
            continue

        matched_events = tuple(item[1] for item in actor_window)
        alerts.append(
            _build_alert(
                kind="brute_force",
                severity="high",
                actor=event.actor,
                events=matched_events,
                summary=(
                    f"{event.actor} produced {len(matched_events)} failed events "
                    f"within {int(window_seconds)} seconds."
                ),
            )
        )
        active_actors.add(event.actor)

    return alerts


def correlate(events: list[NormalizedEvent]) -> list[Alert]:
    """Run all enabled correlation rules."""
    return detect_brute_force(events)
