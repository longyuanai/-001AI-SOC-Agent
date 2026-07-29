"""Offline enrichment primitives for normalized SOC events.

ENRICH-001 deliberately trusts only upstream Geo metadata. It performs no
network requests, ships no GeoIP database, and adds no production dependency.
"""

from __future__ import annotations

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


UPSTREAM_GEO_ENRICHER = UpstreamGeoEnricher()


def enrich_event_geo(event: NormalizedEvent) -> NormalizedEvent:
    """Run one event through the default upstream-only Geo enricher."""
    return UPSTREAM_GEO_ENRICHER.enrich_event(event)


def enrich_events_geo(
    events: Iterable[NormalizedEvent],
) -> list[NormalizedEvent]:
    """Run an event iterable through the default upstream-only Geo enricher."""
    return UPSTREAM_GEO_ENRICHER.enrich_events(events)


__all__ = [
    "CONTINENT_CODES",
    "UPSTREAM_GEO_ENRICHER",
    "UpstreamGeoEnricher",
    "enrich_event_geo",
    "enrich_events_geo",
]
