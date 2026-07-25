"""MITRE ATT&CK T1110 brute-force burst detection."""

from __future__ import annotations

import ipaddress
from typing import Any

from shared_llm_core.finding import FindingSeverity
from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import (
    DEFAULT_BRUTE_FORCE_THRESHOLD,
    DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
)
from ai_soc_agent.patterns.base import (
    SOCPattern,
    alert_metadata,
    context_events,
    context_suppression,
    count_threshold,
    event_value,
    qualifying_windows,
)


def _ip_actor(event: Any) -> str | None:
    actor = str(event_value(event, "actor", event_value(event, "src_ip", "")))
    try:
        return str(ipaddress.ip_address(actor))
    except ValueError:
        return None


class BruteForceBurstRule(SOCPattern):
    """Detect at least five failed logins from one IP within 60 seconds."""

    id = "001.mitre.t1110.brute-force-burst"
    tactic = "TA0006"
    technique = "T1110"
    confidence_default = 0.92

    def matched_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        threshold = ctx.facts.get("brute_force_threshold", DEFAULT_BRUTE_FORCE_THRESHOLD)
        window_seconds = ctx.facts.get(
            "brute_force_window_seconds", DEFAULT_BRUTE_FORCE_WINDOW_SECONDS
        )
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
            return ()
        if not isinstance(window_seconds, (int, float)) or window_seconds <= 0:
            return ()
        return qualifying_windows(
            context_events(ctx),
            group_key=_ip_actor,
            predicate=lambda event: event_value(event, "result") == "failure"
            and "login" in str(event_value(event, "action", "")).casefold(),
            seconds=float(window_seconds),
            qualifies=count_threshold(threshold),
            suppression=context_suppression(ctx),
        )

    def severity(self, ctx: RuleContext, events: tuple[Any, ...]) -> FindingSeverity:
        """Escalate once a burst runs well past the configured threshold."""
        threshold = ctx.facts.get("brute_force_threshold", DEFAULT_BRUTE_FORCE_THRESHOLD)
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
            threshold = DEFAULT_BRUTE_FORCE_THRESHOLD
        return (
            FindingSeverity.CRITICAL
            if len(events) >= threshold * 4
            else FindingSeverity.HIGH
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Brute force from {_ip_actor(events[-1]) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        window_seconds = int(ctx.facts.get("brute_force_window_seconds", 60))
        return (
            f"{len(events)} failed login events from one IP within "
            f"{window_seconds} seconds."
        )

    def finding_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        return alert_metadata(
            kind="brute_force", actor=_ip_actor(events[-1]), events=events
        )
