"""MITRE ATT&CK T1110 brute-force burst detection."""

from __future__ import annotations

import ipaddress
from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.patterns.base import (
    SOCPattern,
    context_events,
    event_value,
    first_group_window,
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

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        threshold = ctx.facts.get("brute_force_threshold", 5)
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
            return ()
        return first_group_window(
            context_events(ctx),
            group_key=_ip_actor,
            predicate=lambda event: event_value(event, "result") == "failure"
            and "login" in str(event_value(event, "action", "")).casefold(),
            threshold=threshold,
            seconds=60,
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Brute force from {_ip_actor(events[-1]) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"{len(events)} failed login events from one IP within 60 seconds."
