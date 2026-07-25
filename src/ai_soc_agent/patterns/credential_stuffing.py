"""MITRE ATT&CK T1110.004 credential-stuffing detection."""

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


def _credential(event: Any) -> str | None:
    for key in ("password_hash", "credential_hash", "password_fingerprint"):
        value = event_value(event, key)
        if value not in (None, "", "-", "unknown"):
            return str(value)
    return None


def _user(event: Any) -> str | None:
    value = event_value(
        event,
        "user",
        event_value(event, "username", event_value(event, "target")),
    )
    return str(value).casefold() if value not in (None, "", "-", "unknown") else None


class CredentialStuffingRule(SOCPattern):
    """Detect one credential fingerprint failing against three user accounts."""

    id = "001.mitre.t1110.004.credential-stuffing"
    tactic = "TA0006"
    technique = "T1110.004"
    confidence_default = 0.91

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        groups: dict[str, list[Any]] = defaultdict(list)
        for event in sorted(context_events(ctx), key=timestamp_key):
            credential = _credential(event)
            user = _user(event)
            if (
                credential is None
                or user is None
                or event_value(event, "result") != "failure"
            ):
                continue
            group = groups[credential]
            group.append(event)
            end = timestamp_key(event)
            group[:] = [item for item in group if end - timestamp_key(item) <= 300]
            by_user = {_user(item): item for item in group}
            if len(by_user) >= 3:
                return tuple(by_user.values())
        return ()

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        actor = event_value(events[-1], "actor", "unknown")
        return f"Credential stuffing from {actor}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        users = sorted({_user(event) for event in events if _user(event)})
        return f"One credential fingerprint failed against users: {', '.join(users)}."
