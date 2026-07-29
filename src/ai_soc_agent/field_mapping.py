"""Deterministic source-specific field mapping for normalized SOC events.

The pipeline adds canonical aliases inside ``NormalizedEvent.extra``. It never
changes the frozen event schema, removes vendor fields, enriches from a network
service, or invents sensitive fields.
"""

from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import Any, Iterable

from ai_soc_agent.normalizer import NormalizedEvent

_SERVICE_BY_SOURCE = {
    "sshd": "ssh",
    "ssh": "ssh",
    "windows": "windows-auth",
    "evtx": "windows-auth",
    "nginx": "http",
    "okta": "okta",
}
_EMPTY_VALUES = frozenset({"", "-", "unknown", "none", "null"})


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.casefold() in _EMPTY_VALUES else text


def _first(extra: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = extra.get(key)
        if _text(value) is not None:
            return value
    return None


def _ip(value: Any) -> str | None:
    text = _text(value)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _canonical_user(event: NormalizedEvent) -> str | None:
    extra = event.extra
    explicit = _text(_first(extra, "user", "username", "account"))
    if explicit is not None:
        return explicit

    source = event.source.casefold()
    if source == "nginx":
        return _text(extra.get("remote_user"))
    if source in {"sshd", "ssh", "windows", "evtx", "okta"}:
        return _text(event.target)
    return _text(_first(extra, "remote_user", "subject_user"))


def _canonical_host(event: NormalizedEvent) -> str | None:
    return _text(
        _first(
            event.extra,
            "host",
            "destination_host",
            "dest_host",
            "computer",
        )
    )


class FieldMappingPipeline:
    """Map parser-specific fields onto a small canonical detection vocabulary."""

    def map_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Return a mapped copy while preserving every original extra field."""
        source = event.source.casefold()
        derived: dict[str, Any] = {}

        if (src_ip := _ip(event.actor)) is not None:
            derived["src_ip"] = src_ip
        if (user := _canonical_user(event)) is not None:
            derived["user"] = user
        if (host := _canonical_host(event)) is not None:
            derived["host"] = host
            derived["destination_host"] = host

        service = _text(event.extra.get("service"))
        if service is None:
            service = _SERVICE_BY_SOURCE.get(source)
        if service is not None:
            derived["service"] = service

        if (process := _text(_first(event.extra, "process", "process_name"))) is not None:
            derived["process"] = process

        if source == "nginx":
            if (method := _text(event.extra.get("method"))) is not None:
                derived["http_method"] = method
            status = event.extra.get("status")
            if isinstance(status, int) and not isinstance(status, bool):
                derived["http_status"] = status

        if source == "okta":
            if (application := _text(
                _first(event.extra, "application", "target_app")
            )) is not None:
                derived["application"] = application

        # Explicit upstream canonical values are authoritative. This also keeps
        # the operation idempotent when an event passes through the pipeline
        # more than once.
        return replace(event, extra={**derived, **event.extra})

    def map_events(
        self, events: Iterable[NormalizedEvent]
    ) -> list[NormalizedEvent]:
        """Map an event iterable once, preserving input order."""
        return [self.map_event(event) for event in events]


DEFAULT_FIELD_MAPPING = FieldMappingPipeline()


def map_event_fields(event: NormalizedEvent) -> NormalizedEvent:
    """Map one event through the default pipeline."""
    return DEFAULT_FIELD_MAPPING.map_event(event)


def map_events(events: Iterable[NormalizedEvent]) -> list[NormalizedEvent]:
    """Map an event iterable through the default pipeline."""
    return DEFAULT_FIELD_MAPPING.map_events(events)


__all__ = [
    "DEFAULT_FIELD_MAPPING",
    "FieldMappingPipeline",
    "map_event_fields",
    "map_events",
]
