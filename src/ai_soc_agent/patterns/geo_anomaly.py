"""MITRE ATT&CK T1078 geographically anomalous login detection.

Requires a ``continent`` field in ``extra``. No parser populates it, so events
must be GeoIP-enriched upstream — see ``docs/tech-spec.md``.
"""

from __future__ import annotations

from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import (
    DEFAULT_GEO_CONTINENT_THRESHOLD,
    DEFAULT_GEO_WINDOW_SECONDS,
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
    confidence_default = 0.90

    def matched_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        return qualifying_windows(
            context_events(ctx),
            group_key=_user,
            predicate=lambda event: event_value(event, "result") == "success"
            and _continent(event) is not None,
            seconds=DEFAULT_GEO_WINDOW_SECONDS,
            qualifies=distinct_threshold(_continent, DEFAULT_GEO_CONTINENT_THRESHOLD),
            suppression=context_suppression(ctx),
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        return f"Geographically anomalous login for {_user(events[-1]) or ctx.subject}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        continents = sorted({_continent(event) or "unknown" for event in events})
        return f"Successful logins crossed continents: {', '.join(continents)}."

    def finding_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        user = _user(events[-1])
        return alert_metadata(
            kind="geo_anomaly",
            actor=user,
            events=events,
            targets=[user] if user else [],
        )
