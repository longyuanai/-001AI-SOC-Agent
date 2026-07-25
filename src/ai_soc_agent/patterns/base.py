"""Base primitives for SOC-specific MITRE ATT&CK rules."""

from __future__ import annotations

from abc import abstractmethod
from collections import defaultdict, deque
from datetime import UTC, datetime
from typing import Any, Callable, Hashable, Sequence

from shared_llm_core.finding import Finding, FindingSeverity
from shared_llm_core.rule_engine import Rule, RuleContext

from ai_soc_agent.config import MAX_WINDOW_EVENTS, Suppression
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


def source_family(event: Any) -> str:
    """Collapse a source name onto its authentication family.

    Single definition on purpose: correlator.py and credential_stuffing.py each
    had one and they had already drifted apart.
    """
    source = str(event_value(event, "source", "")).strip().casefold()
    if "ssh" in source:
        return "ssh"
    if "vpn" in source:
        return "vpn"
    if source in {"nginx", "okta", "web", "http", "https"}:
        return "web"
    return source


def event_evidence(event: Any) -> str:
    """Prefer the original log text, falling back to the normalized event."""
    raw = event_value(event, "raw")
    return str(raw) if raw not in (None, "") else str(event)


def context_suppression(ctx: RuleContext) -> Suppression | None:
    """Return the allowlist supplied to this evaluation, if any."""
    suppression = ctx.facts.get("suppression")
    return suppression if isinstance(suppression, Suppression) else None


def qualifying_windows(
    events: tuple[Any, ...],
    *,
    group_key: Callable[[Any], Hashable | None],
    predicate: Callable[[Any], bool],
    seconds: float,
    qualifies: Callable[[Sequence[tuple[float, Any]]], tuple[Any, ...] | None],
    suppression: Suppression | None = None,
) -> tuple[tuple[Any, ...], ...]:
    """Return the first qualifying sliding window for *each* group.

    One window per group key, in the order the groups first qualified. Emitting
    per group is what lets a scan report every brute-forcing IP instead of only
    the earliest one; capping at the first window per group is what stops a
    sustained attack from emitting a near-duplicate finding per extra event.

    Timestamps are computed once up front — recomputing them inside the sliding
    loop meant re-parsing ISO strings O(n) times per group.
    """
    stamped: list[tuple[float, Hashable, Any]] = []
    for event in events:
        if event_timestamp(event) is None or not predicate(event):
            continue
        key = group_key(event)
        if key is None or (suppression is not None and suppression.suppresses(key)):
            continue
        stamped.append((timestamp_key(event), key, event))
    stamped.sort(key=lambda item: item[0])

    windows: dict[Hashable, deque[tuple[float, Any]]] = defaultdict(deque)
    matched: dict[Hashable, tuple[Any, ...]] = {}
    for timestamp, key, event in stamped:
        window = windows[key]
        window.append((timestamp, event))
        while window and timestamp - window[0][0] > seconds:
            window.popleft()
        while len(window) > MAX_WINDOW_EVENTS:
            window.popleft()
        evidence = qualifies(window)
        # Keep the widest evidence this group ever reaches rather than stopping
        # at the first qualifying window: severity and the analyst's view should
        # reflect the whole burst, not just the events that crossed the line.
        if evidence is not None and (
            key not in matched or len(evidence) > len(matched[key])
        ):
            matched[key] = evidence
    return tuple(matched.values())


WindowQualifier = Callable[[Sequence[tuple[float, Any]]], "tuple[Any, ...] | None"]


def count_threshold(threshold: int) -> WindowQualifier:
    """Qualify a window once it holds ``threshold`` events."""

    def _qualifies(window: Sequence[tuple[float, Any]]) -> tuple[Any, ...] | None:
        if len(window) < threshold:
            return None
        return tuple(event for _, event in window)

    return _qualifies


def distinct_threshold(
    dimension: Callable[[Any], Hashable | None], threshold: int
) -> WindowQualifier:
    """Qualify a window once it spans ``threshold`` distinct dimension values.

    The evidence is one representative event per distinct value, so a finding
    shows the breadth of the attack rather than repeating one host or user.
    """

    def _qualifies(window: Sequence[tuple[float, Any]]) -> tuple[Any, ...] | None:
        seen: dict[Hashable, Any] = {}
        for _, event in window:
            value = dimension(event)
            if value is not None:
                seen.setdefault(value, event)
        return tuple(seen.values()) if len(seen) >= threshold else None

    return _qualifies


def alert_metadata(
    *,
    kind: str,
    actor: Any,
    events: tuple[Any, ...],
    targets: list[str] | None = None,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    """Build the metadata block that ``_finding_to_alert`` needs.

    Every rule must supply it: ``_finding_to_alert`` silently drops findings
    whose metadata lacks these keys, which is how three of the five patterns
    used to vanish between the CLI and the ``/alerts`` API.
    """
    if targets is None:
        targets = sorted(
            {
                str(event_value(event, "target"))
                for event in events
                if event_value(event, "target") not in (None, "", "-", "unknown")
            }
        )
    if sources is None:
        sources = sorted(
            {
                str(event_value(event, "source"))
                for event in events
                if event_value(event, "source") not in (None, "")
            }
        )
    ordered = sorted(events, key=timestamp_key)
    first_ts = event_timestamp(ordered[0]) if ordered else None
    last_ts = event_timestamp(ordered[-1]) if ordered else None
    return {
        "alert_kind": kind,
        "actor": None if actor is None else str(actor),
        "targets": targets,
        "sources": sources,
        "event_count": len(events),
        "first_seen": first_ts.isoformat() if first_ts is not None else "",
        "last_seen": last_ts.isoformat() if last_ts is not None else "",
    }


class SOCPattern(Rule):
    """SOC Rule base with deterministic Finding construction and no live API."""

    tactic: str
    technique: str
    severity_default = FindingSeverity.HIGH
    confidence_default = 0.85
    severity_hint = "high"

    @abstractmethod
    def matched_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        """Return one evidence window per independently matching group."""

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        """Return the first matching evidence window, else empty."""
        groups = self.matched_groups(ctx)
        return groups[0] if groups else ()

    def match(self, ctx: RuleContext) -> bool:
        """Return whether this pattern recognizes the supplied context."""
        return bool(self.matched_groups(ctx))

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

    def severity(self, ctx: RuleContext, events: tuple[Any, ...]) -> FindingSeverity:
        """Return this window's severity."""
        return self.severity_default

    def confidence(self, ctx: RuleContext, events: tuple[Any, ...]) -> float:
        """Return this window's confidence."""
        return self.confidence_default

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        """Return one standard v0.5 Finding per independently matching group."""
        return [self._build(ctx, events) for events in self.matched_groups(ctx)]

    def _build(self, ctx: RuleContext, events: tuple[Any, ...]) -> Finding:
        latest = max(events, key=timestamp_key)
        return build_soc_finding(
            severity=self.severity(ctx, events),
            confidence=self.confidence(ctx, events),
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
