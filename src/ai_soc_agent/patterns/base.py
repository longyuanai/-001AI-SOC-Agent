"""Base primitives for SOC-specific MITRE ATT&CK rules."""

from __future__ import annotations

from abc import abstractmethod
from datetime import UTC, datetime
from typing import Any, Callable, Hashable

from shared_llm_core.finding import Finding, FindingSeverity
from shared_llm_core.rule_engine import Rule, RuleContext

from ai_soc_agent.findings import build_soc_finding, correlation_host


def event_value(event: Any, key: str, default: Any = None) -> Any:
    """Read one normalized-event field from an object or mapping."""
    if isinstance(event, dict):
        if key in event:
            return event[key]
        extra = event.get("extra", {})
    else:
        if hasattr(event, key):
            return getattr(event, key)
        extra = getattr(event, "extra", {})
    return extra.get(key, default) if isinstance(extra, dict) else default


def event_timestamp(event: Any) -> datetime | None:
    """Return an event timestamp, accepting ISO strings in gateway payloads."""
    value = event_value(event, "ts")
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def timestamp_key(event: Any) -> float:
    """Return a sortable UTC timestamp; malformed timestamps sort first."""
    value = event_timestamp(event)
    if value is None:
        return float("-inf")
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).timestamp()


def context_events(ctx: RuleContext) -> tuple[Any, ...]:
    """Return the immutable event sequence supplied to a pattern."""
    events = ctx.facts.get("events", ())
    if not isinstance(events, (list, tuple)):
        return ()
    return tuple(events)


def event_host(event: Any) -> str | None:
    """Extract a correlation-safe IP/host without changing Finding schema."""
    return correlation_host(event)


def event_evidence(event: Any) -> str:
    """Prefer the original log text, falling back to the normalized event."""
    raw = event_value(event, "raw")
    return str(raw) if raw not in (None, "") else str(event)


def first_group_window(
    events: tuple[Any, ...],
    *,
    group_key: Callable[[Any], Hashable | None],
    predicate: Callable[[Any], bool],
    threshold: int,
    seconds: float,
) -> tuple[Any, ...]:
    """Return the first grouped sliding window reaching a threshold."""
    groups: dict[Hashable, list[Any]] = {}
    for event in sorted(events, key=timestamp_key):
        if event_timestamp(event) is None or not predicate(event):
            continue
        key = group_key(event)
        if key is None:
            continue
        group = groups.setdefault(key, [])
        group.append(event)
        end = timestamp_key(event)
        while group and end - timestamp_key(group[0]) > seconds:
            group.pop(0)
        if len(group) >= threshold:
            return tuple(group)
    return ()


class SOCPattern(Rule):
    """SOC Rule base with deterministic Finding construction and no live API."""

    tactic: str
    technique: str
    severity_default = FindingSeverity.HIGH
    confidence_default = 0.85
    severity_hint = "high"

    @abstractmethod
    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        """Return the evidence window when the pattern matches, else empty."""

    def match(self, ctx: RuleContext) -> bool:
        """Return whether this pattern recognizes the supplied context."""
        return bool(self.matched_events(ctx))

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        """Return a concise Finding title."""
        return f"{self.technique} detected for {ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        """Return a deterministic Finding description."""
        return f"{len(events)} events matched {self.id}."

    def finding_host(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        """Select the host used by cross-product correlation."""
        return event_host(events[-1]) if events else None

    def finding_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        """Return pattern-specific metadata without changing Finding schema."""
        return {}

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        """Evaluate this pure rule and return a standard v0.5 Finding."""
        events = self.matched_events(ctx)
        if not events:
            return []
        latest = max(events, key=timestamp_key)
        return [
            build_soc_finding(
                severity=self.severity_default,
                confidence=self.confidence_default,
                title=self.title(ctx, events),
                description=self.description(ctx, events),
                host_event=events[-1],
                host=self.finding_host(ctx, events),
                ts=event_timestamp(latest),
                evidence=tuple(event_evidence(event) for event in events),
                tags=frozenset({"mitre-attack", self.tactic, self.technique}),
                metadata={
                    "rule_id": self.id,
                    "tactic": self.tactic,
                    "technique": self.technique,
                    **self.finding_metadata(ctx, events),
                },
            )
        ]
