"""Base primitives for SOC-specific MITRE ATT&CK rules."""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Callable, Hashable
from datetime import UTC, datetime
from typing import Any

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


def positive_number(value: Any, default: float) -> float | None:
    """Coerce a rule fact to a positive number, or None when it is unusable."""
    if value is None:
        return float(default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value > 0 else None


def positive_int(value: Any, default: int) -> int | None:
    """Coerce a rule fact to a positive integer, or None when it is unusable."""
    if value is None:
        return int(default)
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def event_host(event: Any) -> str | None:
    """Extract a correlation-safe IP/host without changing Finding schema."""
    return correlation_host(event)


def event_evidence(event: Any) -> str:
    """Prefer the original log text, falling back to the normalized event."""
    raw = event_value(event, "raw")
    return str(raw) if raw not in (None, "") else str(event)


def count_windows(
    events: tuple[Any, ...],
    *,
    group_key: Callable[[Any], Hashable | None],
    predicate: Callable[[Any], bool],
    threshold: int,
    seconds: float,
) -> tuple[tuple[Any, ...], ...]:
    """Return the first qualifying sliding window for *each* group key.

    One window per group, not one for the whole batch: three IPs brute-forcing
    at once produce three windows, which is what an analyst expects to triage.
    """
    groups: dict[Hashable, list[Any]] = {}
    matched: dict[Hashable, tuple[Any, ...]] = {}
    for event in sorted(events, key=timestamp_key):
        if event_timestamp(event) is None or not predicate(event):
            continue
        key = group_key(event)
        if key is None or key in matched:
            continue
        group = groups.setdefault(key, [])
        group.append(event)
        end = timestamp_key(event)
        while group and end - timestamp_key(group[0]) > seconds:
            group.pop(0)
        if len(group) >= threshold:
            matched[key] = tuple(group)
    return tuple(matched.values())


def distinct_windows(
    events: tuple[Any, ...],
    *,
    group_key: Callable[[Any], Hashable | None],
    distinct_key: Callable[[Any], Hashable | None],
    predicate: Callable[[Any], bool],
    threshold: int,
    seconds: float,
) -> tuple[tuple[Any, ...], ...]:
    """Return, per group, the first window covering ``threshold`` distinct keys.

    For rules whose signal is breadth rather than volume: one user seen on
    several continents, one account failing across several source families.
    """
    groups: dict[Hashable, list[Any]] = {}
    matched: dict[Hashable, tuple[Any, ...]] = {}
    for event in sorted(events, key=timestamp_key):
        if event_timestamp(event) is None or not predicate(event):
            continue
        key = group_key(event)
        if key is None or key in matched or distinct_key(event) is None:
            continue
        group = groups.setdefault(key, [])
        group.append(event)
        end = timestamp_key(event)
        group[:] = [item for item in group if end - timestamp_key(item) <= seconds]
        by_distinct: dict[Hashable, Any] = {}
        for item in group:
            by_distinct[distinct_key(item)] = item
        if len(by_distinct) >= threshold:
            matched[key] = tuple(by_distinct.values())
    return tuple(matched.values())


def latest_event(events: tuple[Any, ...]) -> Any:
    """Return the newest event in a window, which need not be its last item."""
    return max(events, key=timestamp_key)


def _iso(event: Any) -> str:
    """Render an event timestamp for alert metadata."""
    ts = event_timestamp(event)
    return ts.isoformat() if ts is not None else str(event_value(event, "ts"))


class SOCPattern(Rule):
    """SOC Rule base with deterministic Finding construction and no live API."""

    tactic: str
    technique: str
    #: Stable ``Alert.type`` value surfaced by the ``/alerts`` API.
    alert_kind: str
    severity_default = FindingSeverity.HIGH
    confidence_default = 0.85
    severity_hint = "high"

    @abstractmethod
    def matched_event_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        """Return one evidence window per independent match, else empty."""

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        """Return the first evidence window; convenience for single-match callers."""
        groups = self.matched_event_groups(ctx)
        return groups[0] if groups else ()

    def match(self, ctx: RuleContext) -> bool:
        """Return whether this pattern recognizes the supplied context."""
        return bool(self.matched_event_groups(ctx))

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        """Return a concise Finding title."""
        return f"{self.technique} detected for {ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        """Return a deterministic Finding description."""
        return f"{len(events)} events matched {self.id}."

    def finding_host(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        """Select the host used by cross-product correlation."""
        return event_host(latest_event(events)) if events else None

    def alert_actor(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        """Return the entity an analyst would pivot on (IP, user, account)."""
        actor = event_value(latest_event(events), "actor")
        return str(actor) if actor not in (None, "", "-", "unknown") else None

    def alert_targets(self, ctx: RuleContext, events: tuple[Any, ...]) -> list[str]:
        """Return what the actor went after, deduplicated and sorted."""
        return sorted(
            {
                str(event_value(event, "target"))
                for event in events
                if event_value(event, "target") not in (None, "", "-", "unknown")
            }
        )

    def alert_sources(self, ctx: RuleContext, events: tuple[Any, ...]) -> list[str]:
        """Return the log sources that contributed evidence."""
        return sorted(
            {
                str(event_value(event, "source"))
                for event in events
                if event_value(event, "source") not in (None, "")
            }
        )

    def extra_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        """Hook for rule-specific metadata beyond the shared alert fields."""
        return {}

    def finding_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        """Return the alert-shaped metadata every SOC pattern must carry.

        ``correlator._finding_to_alert`` reads these keys. Building them in the
        base class rather than per-rule is what keeps all five patterns visible
        on ``/alerts`` instead of only the two that used to implement it by hand.
        """
        ordered = sorted(events, key=timestamp_key)
        return {
            "alert_kind": self.alert_kind,
            "actor": self.alert_actor(ctx, events),
            "targets": self.alert_targets(ctx, events),
            "sources": self.alert_sources(ctx, events),
            "event_count": len(events),
            "first_seen": _iso(ordered[0]),
            "last_seen": _iso(ordered[-1]),
            **self.extra_metadata(ctx, events),
        }

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        """Return one v0.5 Finding per independent match in this context."""
        findings = []
        for events in self.matched_event_groups(ctx):
            latest = latest_event(events)
            findings.append(
                build_soc_finding(
                    severity=self.severity_default,
                    confidence=self.confidence_default,
                    title=self.title(ctx, events),
                    description=self.description(ctx, events),
                    host_event=latest,
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
            )
        return findings
