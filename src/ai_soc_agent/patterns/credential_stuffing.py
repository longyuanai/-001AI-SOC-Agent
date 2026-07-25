"""MITRE ATT&CK T1110.004 credential-stuffing detection.

Two modes share one rule:

- default: one credential fingerprint failing against several accounts. Needs a
  ``password_hash``-style field, which no built-in parser produces yet, so it
  only fires on pre-enriched input.
- ``credential_stuffing_mode="cross_source"``: one account failing across the
  ssh / vpn / web families. This is the mode the API and CLI drive.
"""

from __future__ import annotations

from typing import Any, Sequence

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import (
    DEFAULT_CREDENTIAL_USER_THRESHOLD,
    DEFAULT_CREDENTIAL_WINDOW_SECONDS,
    DEFAULT_CROSS_SOURCE_WINDOW_SECONDS,
    DEFAULT_REQUIRED_FAMILIES,
)
from ai_soc_agent.patterns.base import (
    SOCPattern,
    alert_metadata,
    context_events,
    context_suppression,
    distinct_threshold,
    event_value,
    qualifying_windows,
    source_family,
)

_CREDENTIAL_KEYS = ("password_hash", "credential_hash", "password_fingerprint")
_USER_KEYS = ("user", "username", "remote_user", "account")


def _credential(event: Any) -> str | None:
    for key in _CREDENTIAL_KEYS:
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


def _cross_source_user(event: Any) -> str | None:
    for key in _USER_KEYS:
        value = event_value(event, key)
        if value not in (None, "", "-", "unknown"):
            return str(value).casefold()
    target = event_value(event, "target")
    if target in (None, "", "-", "unknown") or (
        source_family(event) == "web" and str(target).startswith("/")
    ):
        return None
    return str(target).casefold()


def _is_failure(event: Any) -> bool:
    return event_value(event, "result") == "failure"


class CredentialStuffingRule(SOCPattern):
    """Detect one credential reused across accounts, or one account failing
    across several source families."""

    id = "001.mitre.t1110.004.credential-stuffing"
    tactic = "TA0006"
    technique = "T1110.004"
    confidence_default = 0.91

    def _is_cross_source(self, ctx: RuleContext) -> bool:
        return ctx.facts.get("credential_stuffing_mode") == "cross_source"

    def matched_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        if self._is_cross_source(ctx):
            return self._cross_source_groups(ctx)
        return qualifying_windows(
            context_events(ctx),
            group_key=_credential,
            predicate=lambda event: _is_failure(event) and _user(event) is not None,
            seconds=DEFAULT_CREDENTIAL_WINDOW_SECONDS,
            qualifies=distinct_threshold(_user, DEFAULT_CREDENTIAL_USER_THRESHOLD),
            suppression=context_suppression(ctx),
        )

    def _cross_source_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        required = frozenset(ctx.facts.get("required_families", DEFAULT_REQUIRED_FAMILIES))
        window_seconds = float(
            ctx.facts.get(
                "credential_stuffing_window_seconds", DEFAULT_CROSS_SOURCE_WINDOW_SECONDS
            )
        )

        def qualifies(window: Sequence[tuple[float, Any]]) -> tuple[Any, ...] | None:
            by_family: dict[str, Any] = {}
            for _, event in window:
                by_family.setdefault(source_family(event), event)
            if not required.issubset(by_family):
                return None
            return tuple(by_family[family] for family in sorted(required))

        return qualifying_windows(
            context_events(ctx),
            group_key=_cross_source_user,
            predicate=lambda event: _is_failure(event) and source_family(event) in required,
            seconds=window_seconds,
            qualifies=qualifies,
            suppression=context_suppression(ctx),
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        actor = event_value(events[-1], "actor", "unknown")
        return f"Credential stuffing from {actor}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        if self._is_cross_source(ctx):
            user = _cross_source_user(events[-1]) or ctx.subject
            families = sorted({source_family(event) for event in events})
            return f"{user} failed authentication across {', '.join(families)}."
        users = sorted({user for event in events if (user := _user(event))})
        return f"One credential fingerprint failed against users: {', '.join(users)}."

    def finding_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        if self._is_cross_source(ctx):
            actor = _cross_source_user(events[-1])
            targets = [actor] if actor else []
        else:
            actor = event_value(events[-1], "actor")
            targets = sorted({user for event in events if (user := _user(event))})
        return alert_metadata(
            kind="credential_stuffing",
            actor=actor,
            events=events,
            targets=targets,
            sources=sorted({source_family(event) for event in events}),
        )
