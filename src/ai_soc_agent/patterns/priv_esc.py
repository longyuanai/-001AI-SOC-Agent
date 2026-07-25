"""MITRE ATT&CK T1548 privilege-escalation anomaly detection."""

from __future__ import annotations

from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.patterns.base import (
    SOCPattern,
    context_events,
    event_value,
    first_group_window,
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
    """Detect three failed sudo attempts by one user within two minutes."""

    id = "001.mitre.t1548.privilege-escalation"
    tactic = "TA0004"
    technique = "T1548"
    confidence_default = 0.87

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        return first_group_window(
            context_events(ctx),
            group_key=_user,
            predicate=_is_failed_sudo,
            threshold=3,
            seconds=120,
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Privilege escalation attempts by {_user(events[-1]) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"{len(events)} failed sudo attempts occurred within 120 seconds."
