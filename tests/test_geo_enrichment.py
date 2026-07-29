"""Offline upstream-only Geo enrichment tests for ENRICH-001."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ai_soc_agent.correlator import detect_patterns
from ai_soc_agent.enrichment import (
    UPSTREAM_GEO_ENRICHER,
    enrich_event_geo,
    enrich_events_geo,
)
from ai_soc_agent.normalizer import NormalizedEvent

NOW = datetime(2026, 7, 29, tzinfo=UTC)


def _event(extra: dict | None = None, *, seconds: int = 0) -> NormalizedEvent:
    return NormalizedEvent(
        ts=NOW + timedelta(seconds=seconds),
        actor="203.0.113.10",
        action="okta_login",
        target="alice@example.test",
        result="success",
        source="okta",
        raw="okta event",
        extra=extra or {},
    )


def test_geo_enrichment_normalizes_lowercase_code() -> None:
    enriched = enrich_event_geo(_event({"continent": "eu"}))

    assert enriched.extra["continent"] == "EU"
    assert enriched.extra["geo_enrichment_status"] == "provided"


def test_geo_enrichment_normalizes_full_name() -> None:
    enriched = enrich_event_geo(_event({"continent": "North America"}))

    assert enriched.extra["continent"] == "NA"


def test_geo_enrichment_accepts_dotted_alias() -> None:
    enriched = enrich_event_geo(_event({"geo.continent_code": "AS"}))

    assert enriched.extra["continent"] == "AS"
    assert enriched.extra["geo_enrichment_source"] == "geo.continent_code"


def test_geo_enrichment_accepts_nested_code() -> None:
    enriched = enrich_event_geo(_event({"geo": {"continent": {"code": "oc"}}}))

    assert enriched.extra["continent"] == "OC"
    assert enriched.extra["geo_enrichment_source"] == "geo.continent.code"


def test_geo_enrichment_accepts_nested_name() -> None:
    enriched = enrich_event_geo(
        _event({"geo": {"continent": {"name": "South America"}}})
    )

    assert enriched.extra["continent"] == "SA"


def test_explicit_continent_wins_over_alias() -> None:
    enriched = enrich_event_geo(
        _event({"continent": "EU", "geo.continent_code": "AS"})
    )

    assert enriched.extra["continent"] == "EU"
    assert enriched.extra["geo_enrichment_source"] == "continent"


def test_invalid_continent_is_excluded_but_auditable() -> None:
    enriched = enrich_event_geo(_event({"continent": "Atlantis"}))

    assert "continent" not in enriched.extra
    assert enriched.extra["geo_continent_raw"] == "Atlantis"
    assert enriched.extra["geo_enrichment_status"] == "invalid"


def test_missing_continent_records_degraded_status() -> None:
    enriched = enrich_event_geo(_event({"user": "alice@example.test"}))

    assert "continent" not in enriched.extra
    assert enriched.extra["geo_enrichment_status"] == "missing"


def test_geo_enrichment_is_idempotent_and_does_not_mutate_input() -> None:
    event = _event({"continent_code": "Europe", "vendor": {"risk": 9}})

    once = enrich_event_geo(event)
    twice = enrich_event_geo(once)

    assert once == twice
    assert event.extra == {"continent_code": "Europe", "vendor": {"risk": 9}}
    assert once.extra["vendor"] == {"risk": 9}


def test_geo_enrichment_maps_iterable_in_order() -> None:
    events = (_event({"continent": "EU"}), _event({"continent": "AS"}))

    enriched = enrich_events_geo(iter(events))

    assert [event.extra["continent"] for event in enriched] == ["EU", "AS"]
    assert UPSTREAM_GEO_ENRICHER.enrich_events(events) == enriched


def test_detect_patterns_uses_upstream_geo_aliases() -> None:
    events = [
        _event({"geo": {"continent": {"code": "EU"}}}, seconds=0),
        _event({"geo.continent": "Asia"}, seconds=30),
    ]

    findings = detect_patterns(events)

    geo_findings = [
        finding
        for finding in findings
        if finding.metadata["rule_id"] == "001.mitre.t1078.geo-anomalous-login"
    ]
    assert len(geo_findings) == 1
    assert "AS, EU" in geo_findings[0].description


def test_invalid_geo_value_cannot_trigger_anomaly() -> None:
    events = [
        _event({"continent": "Atlantis"}, seconds=0),
        _event({"continent": "EU"}, seconds=30),
    ]

    assert all(
        finding.metadata["rule_id"] != "001.mitre.t1078.geo-anomalous-login"
        for finding in detect_patterns(events)
    )
