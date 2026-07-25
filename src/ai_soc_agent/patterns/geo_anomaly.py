"""MITRE ATT&CK T1078 geographically anomalous login detection."""

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
        value = event_value(event, "target")
    return str(value).casefold() if value not in (None, "", "-", "unknown") else None


class GeoAnomalousLoginRule(SOCPattern):
    """Detect one user logging in successfully from multiple continents."""

    id = "001.mitre.t1078.geo-anomalous-login"
    tactic = "TA0001"
    technique = "T1078"
    confidence_default = 0.90

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        groups: dict[str, list[Any]] = defaultdict(list)
        for event in sorted(context_events(ctx), key=timestamp_key):
            continent = event_value(event, "continent")
            user = _user(event)
            if (
                user is None
                or continent in (None, "", "unknown")
                or event_value(event, "result") != "success"
            ):
                continue
            group = groups[user]
            group.append(event)
            end = timestamp_key(event)
            group[:] = [item for item in group if end - timestamp_key(item) <= 86_400]
            by_continent = {
                str(event_value(item, "continent")).upper(): item for item in group
            }
            if len(by_continent) >= 2:
                return tuple(by_continent.values())
        return ()

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Geographically anomalous login for {_user(events[-1]) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        continents = sorted({str(event_value(event, "continent")) for event in events})
        return f"Successful logins crossed continents: {', '.join(continents)}."
