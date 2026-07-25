"""MITRE ATT&CK T1110 brute-force burst detection."""

from __future__ import annotations

import ipaddress
from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_SECONDS
from ai_soc_agent.patterns.base import (
    SOCPattern,
    context_events,
    count_windows,
    event_value,
    latest_event,
    positive_int,
    positive_number,
)


def _ip_actor(event: Any) -> str | None:
    actor = str(event_value(event, "actor", event_value(event, "src_ip", "")))
    try:
        return str(ipaddress.ip_address(actor))
    except ValueError:
        return None


class BruteForceBurstRule(SOCPattern):
    """Detect repeated failed logins from one IP inside a short window."""

    id = "001.mitre.t1110.brute-force-burst"
    tactic = "TA0006"
    technique = "T1110"
    alert_kind = "brute_force"
    confidence_default = 0.92

    def _window_seconds(self, ctx: RuleContext) -> float | None:
        return positive_number(
            ctx.facts.get("brute_force_window_seconds"), BRUTE_FORCE_WINDOW_SECONDS
        )

    def matched_event_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        threshold = positive_int(
            ctx.facts.get("brute_force_threshold"), BRUTE_FORCE_THRESHOLD
        )
        window_seconds = self._window_seconds(ctx)
        if threshold is None or window_seconds is None:
            return ()
        return count_windows(
            context_events(ctx),
            group_key=_ip_actor,
            predicate=lambda event: event_value(event, "result") == "failure"
            and "login" in str(event_value(event, "action", "")).casefold(),
            threshold=threshold,
            seconds=window_seconds,
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Brute force from {_ip_actor(latest_event(events)) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        window_seconds = int(self._window_seconds(ctx) or BRUTE_FORCE_WINDOW_SECONDS)
        return (
            f"{len(events)} failed login events from one IP within "
            f"{window_seconds} seconds."
        )

    def alert_actor(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        return _ip_actor(latest_event(events))
