"""MITRE ATT&CK T1110.004 credential-stuffing detection."""

from __future__ import annotations

from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import (
    CREDENTIAL_STUFFING_CROSS_SOURCE_WINDOW_SECONDS,
    CREDENTIAL_STUFFING_FAMILIES,
    CREDENTIAL_STUFFING_USER_THRESHOLD,
    CREDENTIAL_STUFFING_WINDOW_SECONDS,
    CROSS_SOURCE_MODE,
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


def _source_family(event: Any) -> str:
    source = str(event_value(event, "source", "")).casefold()
    if "ssh" in source:
        return "ssh"
    if "vpn" in source:
        return "vpn"
    if source in {"nginx", "okta", "web", "http", "https"}:
        return "web"
    return source


def _cross_source_user(event: Any) -> str | None:
    for key in ("user", "username", "remote_user", "account"):
        value = event_value(event, key)
        if value not in (None, "", "-", "unknown"):
            return str(value).casefold()
    target = event_value(event, "target")
    if target in (None, "", "-", "unknown") or (
        _source_family(event) == "web" and str(target).startswith("/")
    ):
        return None
    return str(target).casefold()


def _is_failure(event: Any) -> bool:
    return event_value(event, "result") == "failure"


class CredentialStuffingRule(SOCPattern):
    """Detect one credential reused against many accounts, or one account
    failing across several source families in ``cross_source`` mode."""

    id = "001.mitre.t1110.004.credential-stuffing"
    tactic = "TA0006"
    technique = "T1110.004"
    alert_kind = "credential_stuffing"
    confidence_default = 0.91

    def _is_cross_source(self, ctx: RuleContext) -> bool:
        return ctx.facts.get("credential_stuffing_mode") == CROSS_SOURCE_MODE

    def _required_families(self, ctx: RuleContext) -> frozenset[str]:
        return frozenset(
            ctx.facts.get("required_families", CREDENTIAL_STUFFING_FAMILIES)
        )

    def matched_event_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        if self._is_cross_source(ctx):
            return self._cross_source_groups(ctx)

        threshold = positive_int(
            ctx.facts.get("credential_stuffing_user_threshold"),
            CREDENTIAL_STUFFING_USER_THRESHOLD,
        )
        window_seconds = positive_number(
            ctx.facts.get("credential_stuffing_window_seconds"),
            CREDENTIAL_STUFFING_WINDOW_SECONDS,
        )
        if threshold is None or window_seconds is None:
            return ()
        return distinct_windows(
            context_events(ctx),
            group_key=_credential,
            distinct_key=_user,
            predicate=_is_failure,
            threshold=threshold,
            seconds=window_seconds,
        )

    def _cross_source_groups(self, ctx: RuleContext) -> tuple[tuple[Any, ...], ...]:
        required = self._required_families(ctx)
        if not required:
            return ()
        window_seconds = positive_number(
            ctx.facts.get("credential_stuffing_cross_source_window_seconds"),
            CREDENTIAL_STUFFING_CROSS_SOURCE_WINDOW_SECONDS,
        )
        if window_seconds is None:
            return ()
        return distinct_windows(
            context_events(ctx),
            group_key=_cross_source_user,
            distinct_key=_source_family,
            predicate=lambda event: _is_failure(event)
            and _source_family(event) in required,
            threshold=len(required),
            seconds=window_seconds,
        )

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        if self._is_cross_source(ctx):
            user = _cross_source_user(latest_event(events)) or ctx.subject
            return f"Credential stuffing against {user}"
        actor = event_value(latest_event(events), "actor", "unknown")
        return f"Credential stuffing from {actor}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        if self._is_cross_source(ctx):
            user = _cross_source_user(latest_event(events)) or ctx.subject
            families = sorted({_source_family(event) for event in events})
            return f"{user} failed authentication across {', '.join(families)}."
        users = sorted({user for event in events if (user := _user(event))})
        return f"One credential fingerprint failed against users: {', '.join(users)}."

    def alert_actor(self, ctx: RuleContext, events: tuple[Any, ...]) -> str | None:
        if self._is_cross_source(ctx):
            return _cross_source_user(latest_event(events))
        return super().alert_actor(ctx, events)

    def alert_targets(self, ctx: RuleContext, events: tuple[Any, ...]) -> list[str]:
        if self._is_cross_source(ctx):
            actor = _cross_source_user(latest_event(events))
            return [actor] if actor else []
        return sorted({user for event in events if (user := _user(event))})

    def extra_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "source_families": sorted({_source_family(event) for event in events}),
        }
        if not self._is_cross_source(ctx):
            metadata["credential_fingerprint"] = _credential(latest_event(events))
        return metadata
