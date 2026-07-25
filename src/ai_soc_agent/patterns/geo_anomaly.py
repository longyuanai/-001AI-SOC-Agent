"""MITRE ATT&CK T1078 geographically anomalous login detection."""

from __future__ import annotations

from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import (
    GEO_ANOMALY_CONTINENT_THRESHOLD,
    GEO_ANOMALY_WINDOW_SECONDS,
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


def _user(event: Any) -> str | None:
    value = event_value(event, "user", event_value(event, "username"))
    if value in (None, "", "-", "unknown"):
        value = event_value(event, "target")
    return str(value).casefold() if value not in (None, "", "-", "unknown") else None


def _continent(event: Any) -> str | None:
    value = event_value(event, "continent")
    return str(value).upper() if value not in (None, "", "unknown") else None


class GeoAnomalousLoginRule(SOCPattern):
    """Detect one user logging in successfully from multiple continents."""

    id = "001.mitre.t1078.geo-anomalous-login"
    tactic = "TA0001"
    technique = "T1078"
    alert_kind = "geo_anomaly"
    confidence_default = 0.90

    def matched_event_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        threshold = positive_int(
            ctx.facts.get("geo_anomaly_continent_threshold"),
            GEO_ANOMALY_CONTINENT_THRESHOLD,
        )
        window_seconds = positive_number(
            ctx.facts.get("geo_anomaly_window_seconds"), GEO_ANOMALY_WINDOW_SECONDS
        )
        if threshold is None or window_seconds is None:
            return ()
        return distinct_windows(
            context_events(ctx),
            group_key=_user,
            distinct_key=_continent,
            predicate=lambda event: event_value(event, "result") == "success",
            threshold=threshold,
            seconds=window_seconds,
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        user = _user(latest_event(events)) or ctx.subject
        return f"Geographically anomalous login for {user}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        continents = sorted({str(event_value(event, "continent")) for event in events})
        return f"Successful logins crossed continents: {', '.join(continents)}."

    def alert_actor(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        return _user(latest_event(events))

    def extra_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "continents": sorted({c for event in events if (c := _continent(event))}),
            "source_ips": sorted(
                {
                    str(event_value(event, "actor"))
                    for event in events
                    if event_value(event, "actor") not in (None, "", "-", "unknown")
                }
            ),
        }
