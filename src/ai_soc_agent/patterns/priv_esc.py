"""MITRE ATT&CK T1548 privilege-escalation anomaly detection."""

from __future__ import annotations

from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import PRIV_ESC_THRESHOLD, PRIV_ESC_WINDOW_SECONDS
from ai_soc_agent.patterns.base import (
    SOCPattern,
    context_events,
    count_windows,
    event_value,
    latest_event,
    positive_int,
    positive_number,
)


def _user(event: Any) -> str | None:
    value = event_value(event, "user", event_value(event, "username"))
    if value in (None, "", "-", "unknown"):
        value = event_value(event, "actor")
    return str(value).casefold() if value not in (None, "", "-", "unknown") else None


def _is_failed_sudo(event: Any) -> bool:
    action = str(event_value(event, "action", "")).casefold()
    process = str(event_value(event, "process", "")).casefold()
    raw = str(event_value(event, "raw", "")).casefold()
    return event_value(event, "result") == "failure" and (
        "sudo" in action or process == "sudo" or "sudo" in raw
    )


class PrivilegeEscalationRule(SOCPattern):
    """Detect repeated failed sudo attempts by one user in a short window."""

    id = "001.mitre.t1548.privilege-escalation"
    tactic = "TA0004"
    technique = "T1548"
    alert_kind = "privilege_escalation"
    confidence_default = 0.87

    def _window_seconds(self, ctx: RuleContext) -> float | None:
        return positive_number(
            ctx.facts.get("priv_esc_window_seconds"), PRIV_ESC_WINDOW_SECONDS
        )

    def matched_event_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        threshold = positive_int(ctx.facts.get("priv_esc_threshold"), PRIV_ESC_THRESHOLD)
        window_seconds = self._window_seconds(ctx)
        if threshold is None or window_seconds is None:
            return ()
        return count_windows(
            context_events(ctx),
            group_key=_user,
            predicate=_is_failed_sudo,
            threshold=threshold,
            seconds=window_seconds,
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        actor = _user(latest_event(events)) or ctx.subject
        return f"Privilege escalation attempts by {actor}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        window_seconds = int(self._window_seconds(ctx) or PRIV_ESC_WINDOW_SECONDS)
        return f"{len(events)} failed sudo attempts occurred within {window_seconds} seconds."

    def alert_actor(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        return _user(latest_event(events))
