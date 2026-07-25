"""MITRE ATT&CK T1021 lateral-movement detection."""

from __future__ import annotations

from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import (
    DEFAULT_LATERAL_HOST_THRESHOLD,
    DEFAULT_LATERAL_WINDOW_SECONDS,
)
from ai_soc_agent.patterns.base import (
    SOCPattern,
    alert_metadata,
    context_events,
    context_suppression,
    distinct_threshold,
    event_value,
    qualifying_windows,
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
    """Detect one user logging in to at least three hosts within ten minutes."""

    id = "001.mitre.t1021.lateral-movement"
    tactic = "TA0008"
    technique = "T1021"
    confidence_default = 0.88

    def matched_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        return qualifying_windows(
            context_events(ctx),
            group_key=_user,
            predicate=lambda event: _is_remote_login(event)
            and _destination(event) is not None,
            seconds=DEFAULT_LATERAL_WINDOW_SECONDS,
            qualifies=distinct_threshold(_destination, DEFAULT_LATERAL_HOST_THRESHOLD),
            suppression=context_suppression(ctx),
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Lateral movement by {_user(events[-1]) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        hosts = sorted({host for event in events if (host := _destination(event))})
        return f"Successful remote logins reached hosts: {', '.join(hosts)}."

    def finding_host(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        return _destination(events[-1]) if events else None

    def finding_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        return alert_metadata(
            kind="lateral_movement",
            actor=_user(events[-1]),
            events=events,
            targets=sorted({host for event in events if (host := _destination(event))}),
        )
