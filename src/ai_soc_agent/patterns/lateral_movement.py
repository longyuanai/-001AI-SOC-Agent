"""MITRE ATT&CK T1021 lateral-movement detection."""

from __future__ import annotations

from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import (
    LATERAL_MOVEMENT_HOST_THRESHOLD,
    LATERAL_MOVEMENT_WINDOW_SECONDS,
)
from ai_soc_agent.patterns.base import (
    SOCPattern,
    context_events,
    distinct_windows,
    event_value,
    latest_event,
    positive_int,
    positive_number,
)

_REMOTE_TOKENS = ("ssh", "rdp", "winrm", "smb", "remote")


def _user(event: Any) -> str | None:
    value = event_value(event, "user", event_value(event, "username"))
    if value in (None, "", "-", "unknown"):
        actor = event_value(event, "actor")
        value = actor if actor and not str(actor)[0].isdigit() else None
    return str(value).casefold() if value not in (None, "", "-", "unknown") else None


def _destination(event: Any) -> str | None:
    value = event_value(
        event,
        "destination_host",
        event_value(event, "host", event_value(event, "target")),
    )
    return str(value) if value not in (None, "", "-", "unknown") else None


def _is_remote_login(event: Any) -> bool:
    action = str(event_value(event, "action", "")).casefold()
    source = str(event_value(event, "source", "")).casefold()
    return event_value(event, "result") == "success" and any(
        token in action or token in source for token in _REMOTE_TOKENS
    )


class LateralMovementRule(SOCPattern):
    """Detect one user logging in to several hosts within a short window."""

    id = "001.mitre.t1021.lateral-movement"
    tactic = "TA0008"
    technique = "T1021"
    alert_kind = "lateral_movement"
    confidence_default = 0.88

    def matched_event_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        threshold = positive_int(
            ctx.facts.get("lateral_movement_host_threshold"),
            LATERAL_MOVEMENT_HOST_THRESHOLD,
        )
        window_seconds = positive_number(
            ctx.facts.get("lateral_movement_window_seconds"),
            LATERAL_MOVEMENT_WINDOW_SECONDS,
        )
        if threshold is None or window_seconds is None:
            return ()
        return distinct_windows(
            context_events(ctx),
            group_key=_user,
            distinct_key=_destination,
            predicate=_is_remote_login,
            threshold=threshold,
            seconds=window_seconds,
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Lateral movement by {_user(latest_event(events)) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        hosts = sorted({host for event in events if (host := _destination(event))})
        return f"Successful remote logins reached hosts: {', '.join(hosts)}."

    def finding_host(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        return _destination(latest_event(events)) if events else None

    def alert_actor(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        return _user(latest_event(events))

    def alert_targets(self, ctx: RuleContext, events: tuple[Any, ...]) -> list[str]:
        return sorted({host for event in events if (host := _destination(event))})
