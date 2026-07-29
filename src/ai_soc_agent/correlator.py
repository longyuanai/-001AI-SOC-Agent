"""Deterministic, in-memory correlation rules for normalized events."""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from shared_llm_core.finding import Finding
from shared_llm_core.rule_engine import RuleContext, RuleEngine

from ai_soc_agent.config import DetectionConfig
from ai_soc_agent.field_mapping import map_events
from ai_soc_agent.normalizer import NormalizedEvent, ensure_utc
from ai_soc_agent.patterns import build_pattern_engine
from ai_soc_agent.patterns.base import event_timestamp, source_family


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
    targets: tuple[str, ...] | None = None,
) -> Alert:
    sources = tuple(sorted({event.source for event in events}))
    if targets is None:
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


def _event_user(event: NormalizedEvent) -> str | None:
    for key in ("user", "username", "remote_user", "account"):
        value = event.extra.get(key)
        if isinstance(value, str) and value not in ("", "-", "unknown"):
            return value.strip().casefold()

    if source_family(event) == "web" and event.target.startswith("/"):
        return None
    if event.target in ("", "-", "unknown"):
        return None
    return event.target.strip().casefold()


def detect_credential_stuffing(
    events: list[NormalizedEvent],
    *,
    window: timedelta = timedelta(minutes=10),
    required_families: frozenset[str] = frozenset({"ssh", "vpn", "web"}),
) -> list[Alert]:
    """Detect one user failing authentication across SSH, VPN, and web sources."""
    if window.total_seconds() <= 0:
        raise ValueError("window must be positive")
    if not required_families:
        raise ValueError("required_families must not be empty")

    failures = []
    for event in events:
        if event.result != "failure":
            continue
        user = _event_user(event)
        family = source_family(event)
        if user is not None and family in required_families:
            failures.append((_utc_timestamp(event.ts), event, user, family))
    failures.sort(key=lambda item: item[0])

    windows: dict[str, deque[tuple[float, NormalizedEvent, str]]] = defaultdict(deque)
    active_users: set[str] = set()
    alerts: list[Alert] = []
    window_seconds = window.total_seconds()

    for timestamp, event, user, family in failures:
        user_window = windows[user]
        while user_window and timestamp - user_window[0][0] > window_seconds:
            user_window.popleft()
        existing_families = {item[2] for item in user_window}
        if not required_families.issubset(existing_families):
            active_users.discard(user)

        user_window.append((timestamp, event, family))
        observed_families = {item[2] for item in user_window}
        if not required_families.issubset(observed_families) or user in active_users:
            continue

        matched_events = tuple(item[1] for item in user_window)
        alerts.append(
            _build_alert(
                kind="credential_stuffing",
                severity="high",
                actor=user,
                targets=(user,),
                events=matched_events,
                summary=(
                    f"{user} failed authentication across "
                    f"{', '.join(sorted(required_families))} within "
                    f"{int(window_seconds)} seconds."
                ),
            )
        )
        active_users.add(user)

    return alerts


def detect_patterns(
    events: list[NormalizedEvent],
    *,
    facts: dict[str, Any] | None = None,
    engine: RuleEngine | None = None,
) -> list[Finding]:
    """Evaluate all MITRE patterns through the frozen v0.5 RuleEngine."""
    mapped_events = map_events(events)
    merged_facts: dict[str, Any] = {"events": tuple(mapped_events)}
    if facts:
        merged_facts.update(facts)
    # Events may arrive as dicts from the gateway and with mixed tz-awareness,
    # so normalize before comparing instead of calling min()/max() directly.
    timestamps = sorted(
        (
            ensure_utc(ts)
            for event in mapped_events
            if (ts := event_timestamp(event)) is not None
        ),
    )
    context = RuleContext(
        subject="soc-event-stream",
        facts=merged_facts,
        window=(timestamps[0], timestamps[-1]) if timestamps else None,
    )
    selected_engine = engine if engine is not None else build_pattern_engine()
    return selected_engine.evaluate(context)


def _finding_to_alert(finding: Finding) -> Alert | None:
    metadata = finding.metadata
    kind = metadata.get("alert_kind")
    actor = metadata.get("actor")
    first_seen = metadata.get("first_seen")
    last_seen = metadata.get("last_seen")
    if not all(isinstance(value, str) and value for value in (kind, actor, first_seen, last_seen)):
        return None
    first_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
    last_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    sources = tuple(str(value) for value in metadata.get("sources", ()))
    targets = tuple(str(value) for value in metadata.get("targets", ()))
    return Alert(
        id=_alert_id(kind, actor, first_dt, last_dt, sources),
        kind=kind,
        severity=finding.severity.value,
        actor=actor,
        targets=targets,
        first_seen=first_dt,
        last_seen=last_dt,
        event_count=int(metadata.get("event_count", len(finding.evidence))),
        sources=sources,
        summary=finding.description,
    )


def correlate(
    events: list[NormalizedEvent], *, config: DetectionConfig | None = None
) -> list[Alert]:
    """Run compatibility Alert output through the Phase-2 RuleEngine."""
    settings = config if config is not None else DetectionConfig.for_stream()
    findings = detect_patterns(
        events,
        facts={
            **settings.as_facts(),
            "credential_stuffing_mode": "cross_source",
        },
    )
    alerts = [
        alert
        for finding in findings
        if (alert := _finding_to_alert(finding)) is not None
    ]
    return sorted(alerts, key=lambda alert: (_utc_timestamp(alert.first_seen), alert.kind, alert.id))
