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
    if (
        target in (None, "", "-", "unknown")
        or (_source_family(event) == "web" and str(target).startswith("/"))
    ):
        return None
    return str(target).casefold()


class CredentialStuffingRule(SOCPattern):
    """Detect one credential fingerprint failing against three user accounts."""

    id = "001.mitre.t1110.004.credential-stuffing"
    tactic = "TA0006"
    technique = "T1110.004"
    confidence_default = 0.91

    def matched_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        if ctx.facts.get("credential_stuffing_mode") == "cross_source":
            return self._cross_source_events(ctx)

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

    def _cross_source_events(self, ctx: RuleContext) -> tuple[Any, ...]:
        required = frozenset(ctx.facts.get("required_families", {"ssh", "vpn", "web"}))
        window_seconds = float(ctx.facts.get("credential_stuffing_window_seconds", 600))
        groups: dict[str, list[Any]] = defaultdict(list)
        for event in sorted(context_events(ctx), key=timestamp_key):
            user = _cross_source_user(event)
            family = _source_family(event)
            if (
                user is None
                or family not in required
                or event_value(event, "result") != "failure"
            ):
                continue
            group = groups[user]
            group.append(event)
            end = timestamp_key(event)
            group[:] = [
                item for item in group if end - timestamp_key(item) <= window_seconds
            ]
            by_family = {_source_family(item): item for item in group}
            if required.issubset(by_family):
                return tuple(by_family[family] for family in sorted(required))
        return ()

    def title(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        actor = event_value(events[-1], "actor", "unknown")
        return f"Credential stuffing from {actor}"

    def description(self, ctx: RuleContext, events: tuple[Any, ...]) -> str:
        if ctx.facts.get("credential_stuffing_mode") == "cross_source":
            user = _cross_source_user(events[-1]) or ctx.subject
            families = sorted({_source_family(event) for event in events})
            return f"{user} failed authentication across {', '.join(families)}."
        users = sorted({_user(event) for event in events if _user(event)})
        return f"One credential fingerprint failed against users: {', '.join(users)}."

    def finding_metadata(self, ctx: RuleContext, events: tuple[Any, ...]) -> dict[str, Any]:
        if ctx.facts.get("credential_stuffing_mode") == "cross_source":
            actor = _cross_source_user(events[-1])
            targets = [actor] if actor else []
        else:
            actor = event_value(events[-1], "actor")
            targets = sorted({_user(event) for event in events if _user(event)})
        return {
            "alert_kind": "credential_stuffing",
            "actor": actor,
            "targets": targets,
            "sources": sorted({_source_family(event) for event in events}),
            "event_count": len(events),
            "first_seen": str(event_value(events[0], "ts")),
            "last_seen": str(event_value(events[-1], "ts")),
        }
