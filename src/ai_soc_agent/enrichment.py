"""Offline enrichment primitives for normalized SOC events.

ENRICH-001 deliberately trusts only upstream Geo metadata. It performs no
network requests, ships no GeoIP database, and adds no production dependency.
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Iterable

from ai_soc_agent.normalizer import NormalizedEvent

CONTINENT_CODES = frozenset({"AF", "AN", "AS", "EU", "NA", "OC", "SA"})
_CONTINENT_NAMES = {
    "africa": "AF",
    "antarctica": "AN",
    "asia": "AS",
    "europe": "EU",
    "north america": "NA",
    "oceania": "OC",
    "australia": "OC",
    "south america": "SA",
}
_GEO_ENRICHMENT_VERSION = "upstream-v1"
_CREDENTIAL_ENRICHMENT_VERSION = "upstream-hmac-v1"
_CREDENTIAL_KEYS = (
    "credential_fingerprint",
    "password_fingerprint",
    "credential_hash",
    "password_hash",
)
_FINGERPRINT_PATTERN = re.compile(
    r"hmac-sha256:"
    r"(?P<scope>[A-Za-z0-9][A-Za-z0-9._-]{0,63}):"
    r"(?P<digest>[0-9a-fA-F]{64})"
)


def _normalize_continent(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.strip().replace("_", " ").replace("-", " ").split())
    if not text:
        return None
    upper = text.upper()
    if upper in CONTINENT_CODES:
        return upper
    return _CONTINENT_NAMES.get(text.casefold())


def _nested_continent(value: Any) -> tuple[Any, str] | None:
    if not isinstance(value, dict):
        return None
    continent = value.get("continent")
    if isinstance(continent, dict):
        if "code" in continent:
            return continent["code"], "geo.continent.code"
        if "name" in continent:
            return continent["name"], "geo.continent.name"
    elif continent is not None:
        return continent, "geo.continent"
    if "continent_code" in value:
        return value["continent_code"], "geo.continent_code"
    return None


def _continent_candidate(extra: dict[str, Any]) -> tuple[Any, str] | None:
    for key in (
        "continent",
        "continent_code",
        "geo.continent",
        "geo.continent_code",
    ):
        if key in extra:
            value = extra[key]
            if isinstance(value, dict):
                nested = _nested_continent({"continent": value})
                if nested is not None:
                    return nested
            return value, key
    return _nested_continent(extra.get("geo"))


class UpstreamGeoEnricher:
    """Validate and normalize continent metadata supplied by an upstream SIEM."""

    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Return a copy with an auditable Geo enrichment status."""
        extra = dict(event.extra)
        if extra.get("geo_enrichment_version") == _GEO_ENRICHMENT_VERSION:
            return replace(event, extra=extra)

        candidate = _continent_candidate(extra)
        extra["geo_enrichment_version"] = _GEO_ENRICHMENT_VERSION
        if candidate is None:
            extra["geo_enrichment_status"] = "missing"
            return replace(event, extra=extra)

        raw_value, source = candidate
        continent = _normalize_continent(raw_value)
        extra["geo_enrichment_source"] = source
        if continent is None:
            # An invalid canonical value must not reach the geo-anomaly rule.
            # Keep a harmless textual audit value instead of silently losing
            # the upstream data.
            extra.pop("continent", None)
            extra["geo_continent_raw"] = str(raw_value)
            extra["geo_enrichment_status"] = "invalid"
            return replace(event, extra=extra)

        extra["continent"] = continent
        extra["geo_enrichment_status"] = "provided"
        return replace(event, extra=extra)

    def enrich_events(
        self, events: Iterable[NormalizedEvent]
    ) -> list[NormalizedEvent]:
        """Enrich an event iterable once, preserving order."""
        return [self.enrich_event(event) for event in events]


def _credential_candidate(extra: dict[str, Any]) -> tuple[Any, str] | None:
    for key in _CREDENTIAL_KEYS:
        if key in extra:
            return extra[key], key
    return None


def _normalize_credential_fingerprint(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    match = _FINGERPRINT_PATTERN.fullmatch(value.strip())
    if match is None:
        return None
    scope = match.group("scope").casefold()
    digest = match.group("digest").lower()
    return f"hmac-sha256:{scope}:{digest}"


def _credential_safe_evidence(event: NormalizedEvent) -> str:
    """Describe a credential event without copying its secret-derived value."""
    return (
        f"{event.source} {event.action} {event.result} "
        f"actor={event.actor} target={event.target} [credential redacted]"
    )


class UpstreamCredentialEnricher:
    """Accept only scoped HMAC fingerprints supplied by a trusted upstream."""

    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Return a detection copy without retaining unsafe credential values."""
        extra = dict(event.extra)
        if (
            extra.get("credential_enrichment_version")
            == _CREDENTIAL_ENRICHMENT_VERSION
        ):
            return replace(event, extra=extra)

        candidate = _credential_candidate(extra)
        extra["credential_enrichment_version"] = (
            _CREDENTIAL_ENRICHMENT_VERSION
        )
        if candidate is None:
            extra["credential_enrichment_status"] = "missing"
            return replace(event, extra=extra)

        supplied, source = candidate
        # Remove every credential alias before branching. An invalid value may
        # be plaintext or a reversible token, so it is never copied to the
        # prepared event or an audit field.
        for key in _CREDENTIAL_KEYS:
            extra.pop(key, None)
        extra["credential_enrichment_source"] = source
        safe_raw = _credential_safe_evidence(event)

        fingerprint = _normalize_credential_fingerprint(supplied)
        if fingerprint is None:
            extra["credential_enrichment_status"] = "invalid"
            extra["credential_enrichment_reason"] = "invalid_format"
            return replace(event, raw=safe_raw, extra=extra)

        extra["password_fingerprint"] = fingerprint
        extra["credential_enrichment_status"] = "provided"
        return replace(event, raw=safe_raw, extra=extra)

    def enrich_events(
        self, events: Iterable[NormalizedEvent]
    ) -> list[NormalizedEvent]:
        """Enrich an event iterable once, preserving order."""
        return [self.enrich_event(event) for event in events]


UPSTREAM_GEO_ENRICHER = UpstreamGeoEnricher()
UPSTREAM_CREDENTIAL_ENRICHER = UpstreamCredentialEnricher()


def enrich_event_geo(event: NormalizedEvent) -> NormalizedEvent:
    """Run one event through the default upstream-only Geo enricher."""
    return UPSTREAM_GEO_ENRICHER.enrich_event(event)


def enrich_events_geo(
    events: Iterable[NormalizedEvent],
) -> list[NormalizedEvent]:
    """Run an event iterable through the default upstream-only Geo enricher."""
    return UPSTREAM_GEO_ENRICHER.enrich_events(events)


def enrich_event_credential(event: NormalizedEvent) -> NormalizedEvent:
    """Validate one upstream credential fingerprint."""
    return UPSTREAM_CREDENTIAL_ENRICHER.enrich_event(event)


def enrich_events_credentials(
    events: Iterable[NormalizedEvent],
) -> list[NormalizedEvent]:
    """Validate upstream credential fingerprints for an event iterable."""
    return UPSTREAM_CREDENTIAL_ENRICHER.enrich_events(events)


__all__ = [
    "CONTINENT_CODES",
    "UPSTREAM_CREDENTIAL_ENRICHER",
    "UPSTREAM_GEO_ENRICHER",
    "UpstreamCredentialEnricher",
    "UpstreamGeoEnricher",
    "enrich_event_credential",
    "enrich_event_geo",
    "enrich_events_credentials",
    "enrich_events_geo",
]
