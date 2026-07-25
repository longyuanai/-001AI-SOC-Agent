"""Deterministic, in-memory correlation rules for normalized events.

Detection itself lives in :mod:`ai_soc_agent.patterns` and runs through the
frozen v0.5 ``RuleEngine``. This module owns the legacy ``Alert`` projection the
``/alerts`` API still speaks, plus the shared entry point every caller uses so
thresholds cannot drift between the CLI, the API, and the gateway adapter.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from shared_llm_core.finding import Finding
from shared_llm_core.rule_engine import RuleContext, RuleEngine

from ai_soc_agent.config import STREAMING_PROFILE, detection_facts
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.patterns import build_pattern_engine


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


def _as_utc(value: datetime) -> datetime:
    """Treat naive timestamps as UTC so mixed-timezone batches stay comparable."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _utc_timestamp(value: datetime) -> float:
    """Convert mixed naive/aware datetimes to a deterministic UTC timestamp."""
    return _as_utc(value).timestamp()


def _alert_id(kind: str, actor: str) -> str:
    """Derive a stable id from the incident identity, not its window bounds.

    Hashing ``first_seen``/``last_seen`` in here used to mint a fresh id every
    time the sliding window shifted, flooding the store with duplicates of a
    single incident.
    """
    digest = hashlib.sha256(f"{kind}|{actor}".encode()).hexdigest()[:16]
    return f"{kind}-{digest}"


def detect_patterns(
    events: list[NormalizedEvent],
    *,
    facts: dict[str, Any] | None = None,
    engine: RuleEngine | None = None,
) -> list[Finding]:
    """Evaluate all MITRE patterns through the frozen v0.5 RuleEngine."""
    merged_facts = detection_facts(facts)
    merged_facts["events"] = tuple(events)
    # Normalize before comparing: a batch mixing naive and aware timestamps
    # (ELK and Splunk disagree here) used to raise TypeError on min()/max().
    timestamps = sorted(_as_utc(event.ts) for event in events)
    context = RuleContext(
        subject="soc-event-stream",
        facts=merged_facts,
        window=(timestamps[0], timestamps[-1]) if timestamps else None,
    )
    selected_engine = engine if engine is not None else build_pattern_engine()
    return selected_engine.evaluate(context)


def _metadata_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def finding_to_alert(finding: Finding) -> Alert:
    """Project a Finding onto the legacy Alert shape.

    Every field falls back to something derivable from the Finding itself, so a
    pattern missing an optional metadata key degrades to a less precise alert
    instead of vanishing from ``/alerts`` — which is what silently hid three of
    the five patterns from the API.
    """
    metadata = finding.metadata
    kind = str(metadata.get("alert_kind") or metadata.get("rule_id") or "unknown")
    actor = str(metadata.get("actor") or finding.host or "unknown")

    first_seen = _metadata_datetime(metadata.get("first_seen"))
    last_seen = _metadata_datetime(metadata.get("last_seen"))
    fallback = first_seen or last_seen or finding.ts or datetime.now(UTC)

    event_count = metadata.get("event_count")
    if not isinstance(event_count, int) or isinstance(event_count, bool):
        event_count = len(finding.evidence)

    return Alert(
        id=_alert_id(kind, actor),
        kind=kind,
        severity=finding.severity.value,
        actor=actor,
        targets=tuple(str(value) for value in metadata.get("targets", ())),
        first_seen=first_seen or fallback,
        last_seen=last_seen or fallback,
        event_count=event_count,
        sources=tuple(str(value) for value in metadata.get("sources", ())),
        summary=finding.description,
    )


def correlate(events: list[NormalizedEvent]) -> list[Alert]:
    """Run compatibility Alert output through the Phase-2 RuleEngine."""
    findings = detect_patterns(events, facts=STREAMING_PROFILE)
    alerts = [finding_to_alert(finding) for finding in findings]
    return sorted(
        alerts,
        key=lambda alert: (_utc_timestamp(alert.first_seen), alert.kind, alert.id),
    )


__all__ = ["Alert", "correlate", "detect_patterns", "finding_to_alert"]
