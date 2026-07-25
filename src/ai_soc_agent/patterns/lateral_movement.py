"""MITRE ATT&CK T1021 lateral-movement detection."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.patterns.base import (
    SOCPattern,
    context_events,
    event_value,
    timestamp_key,
)


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
        token in action or token in source
        for token in ("ssh", "rdp", "winrm", "smb", "remote")
    )


class LateralMovementRule(SOCPattern):
    """Detect one user logging in to at least three hosts within ten minutes."""

    id = "001.mitre.t1021.lateral-movement"
    tactic = "TA0008"
    technique = "T1021"
    confidence_default = 0.88

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        groups: dict[str, list[Any]] = defaultdict(list)
        for event in sorted(context_events(ctx), key=timestamp_key):
            user = _user(event)
            destination = _destination(event)
            if user is None or destination is None or not _is_remote_login(event):
                continue
            group = groups[user]
            group.append(event)
            end = timestamp_key(event)
            group[:] = [item for item in group if end - timestamp_key(item) <= 600]
            by_host = {_destination(item): item for item in group}
            if len(by_host) >= 3:
                return tuple(by_host.values())
        return ()

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Lateral movement by {_user(events[-1]) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        hosts = sorted({_destination(event) for event in events if _destination(event)})
        return f"Successful remote logins reached hosts: {', '.join(hosts)}."

    def finding_host(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        return _destination(events[-1]) if events else None
