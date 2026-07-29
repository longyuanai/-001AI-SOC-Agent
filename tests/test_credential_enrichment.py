"""Safe upstream credential fingerprint tests for ENRICH-002."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ai_soc_agent.correlator import detect_patterns
from ai_soc_agent.enrichment import (
    UPSTREAM_CREDENTIAL_ENRICHER,
    enrich_event_credential,
    enrich_events_credentials,
)
from ai_soc_agent.normalizer import NormalizedEvent

NOW = datetime(2026, 7, 29, tzinfo=UTC)
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
FINGERPRINT = f"hmac-sha256:tenant-a:{DIGEST}"


def _event(
    user: str = "alice",
    *,
    extra: dict | None = None,
    seconds: int = 0,
) -> NormalizedEvent:
    return NormalizedEvent(
        ts=NOW + timedelta(seconds=seconds),
        actor="203.0.113.20",
        action="web_login",
        target=user,
        result="failure",
        source="nginx",
        raw=f"failed login for {user}",
        extra={"user": user, **(extra or {})},
    )


def test_valid_scoped_hmac_fingerprint_is_accepted() -> None:
    enriched = enrich_event_credential(
        _event(extra={"credential_fingerprint": FINGERPRINT})
    )

    assert enriched.extra["password_fingerprint"] == FINGERPRINT
    assert enriched.extra["credential_enrichment_status"] == "provided"


def test_fingerprint_hex_is_normalized_to_lowercase() -> None:
    supplied = f"hmac-sha256:tenant-a:{DIGEST.upper()}"

    enriched = enrich_event_credential(
        _event(extra={"password_fingerprint": supplied})
    )

    assert enriched.extra["password_fingerprint"] == FINGERPRINT


def test_legacy_alias_is_accepted_only_with_safe_format() -> None:
    enriched = enrich_event_credential(
        _event(extra={"password_hash": FINGERPRINT})
    )

    assert enriched.extra["password_fingerprint"] == FINGERPRINT
    assert enriched.extra["credential_enrichment_source"] == "password_hash"


def test_explicit_canonical_fingerprint_wins_over_alias() -> None:
    canonical = f"hmac-sha256:tenant-a:{DIGEST}"
    alias = f"hmac-sha256:tenant-a:{OTHER_DIGEST}"

    enriched = enrich_event_credential(
        _event(
            extra={
                "credential_fingerprint": canonical,
                "password_hash": alias,
            }
        )
    )

    assert enriched.extra["password_fingerprint"] == canonical
    assert enriched.extra["credential_enrichment_source"] == (
        "credential_fingerprint"
    )


def test_unscoped_legacy_sha256_is_rejected() -> None:
    enriched = enrich_event_credential(
        _event(extra={"password_hash": "sha256:reused-demo"})
    )

    assert enriched.extra["credential_enrichment_status"] == "invalid"
    assert "password_hash" not in enriched.extra
    assert "password_fingerprint" not in enriched.extra


def test_plaintext_like_value_is_rejected_without_copying_raw_value() -> None:
    enriched = enrich_event_credential(
        _event(extra={"credential_fingerprint": "Summer2026!"})
    )

    assert enriched.extra["credential_enrichment_status"] == "invalid"
    assert enriched.extra["credential_enrichment_reason"] == "invalid_format"
    assert "Summer2026!" not in str(enriched.extra)
    assert "Summer2026!" not in enriched.raw
    assert "[credential redacted]" in enriched.raw


def test_missing_fingerprint_records_degraded_status() -> None:
    enriched = enrich_event_credential(_event())

    assert enriched.extra["credential_enrichment_status"] == "missing"
    assert "password_fingerprint" not in enriched.extra


def test_credential_enrichment_is_idempotent_and_preserves_input() -> None:
    event = _event(extra={"credential_hash": FINGERPRINT, "vendor": "kept"})

    once = enrich_event_credential(event)
    twice = enrich_event_credential(once)

    assert once == twice
    assert event.extra["credential_hash"] == FINGERPRINT
    assert once.extra["vendor"] == "kept"


def test_credential_enrichment_maps_iterable_in_order() -> None:
    events = (
        _event("alice", extra={"credential_fingerprint": FINGERPRINT}),
        _event(
            "bob",
            extra={
                "credential_fingerprint": (
                    f"hmac-sha256:tenant-a:{OTHER_DIGEST}"
                )
            },
        ),
    )

    enriched = enrich_events_credentials(iter(events))

    assert [event.extra["user"] for event in enriched] == ["alice", "bob"]
    assert UPSTREAM_CREDENTIAL_ENRICHER.enrich_events(events) == enriched


def test_same_scoped_fingerprint_triggers_credential_stuffing() -> None:
    events = [
        _event(
            user,
            extra={"credential_fingerprint": FINGERPRINT},
            seconds=index,
        )
        for index, user in enumerate(("alice", "bob", "carol"))
    ]

    findings = detect_patterns(events)

    stuffing = [
        finding
        for finding in findings
        if finding.metadata["rule_id"]
        == "001.mitre.t1110.004.credential-stuffing"
    ]
    assert len(stuffing) == 1
    assert stuffing[0].metadata["targets"] == ["alice", "bob", "carol"]
    assert all(FINGERPRINT not in evidence for evidence in stuffing[0].evidence)
    assert all("[credential redacted]" in evidence for evidence in stuffing[0].evidence)


def test_same_digest_in_different_scopes_does_not_correlate() -> None:
    events = [
        _event(
            user,
            extra={
                "credential_fingerprint": (
                    f"hmac-sha256:tenant-{index}:{DIGEST}"
                )
            },
            seconds=index,
        )
        for index, user in enumerate(("alice", "bob", "carol"))
    ]

    assert all(
        finding.metadata["rule_id"]
        != "001.mitre.t1110.004.credential-stuffing"
        for finding in detect_patterns(events)
    )


def test_invalid_fingerprint_cannot_trigger_credential_stuffing() -> None:
    events = [
        _event(
            user,
            extra={"password_hash": "sha256:reused-demo"},
            seconds=index,
        )
        for index, user in enumerate(("alice", "bob", "carol"))
    ]

    assert all(
        finding.metadata["rule_id"]
        != "001.mitre.t1110.004.credential-stuffing"
        for finding in detect_patterns(events)
    )
