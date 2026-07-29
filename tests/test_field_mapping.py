"""Source-specific canonical field mapping tests for FIELD-MAP-001."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ai_soc_agent.correlator import detect_patterns
from ai_soc_agent.field_mapping import (
    DEFAULT_FIELD_MAPPING,
    map_event_fields,
    map_events,
)
from ai_soc_agent.normalizer import NormalizedEvent

NOW = datetime(2026, 7, 29, tzinfo=UTC)


def _event(
    *,
    source: str,
    actor: str,
    target: str,
    action: str = "login",
    result: str = "success",
    extra: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        ts=NOW,
        actor=actor,
        action=action,
        target=target,
        result=result,
        source=source,
        raw="raw evidence",
        extra=extra or {},
    )


def test_sshd_mapping_adds_canonical_user_ip_host_and_service() -> None:
    event = _event(
        source="sshd",
        actor="203.0.113.10",
        target="root",
        action="ssh_login",
        extra={"host": "bastion-01", "auth_method": "publickey"},
    )

    mapped = map_event_fields(event)

    assert mapped.extra["src_ip"] == "203.0.113.10"
    assert mapped.extra["user"] == "root"
    assert mapped.extra["host"] == "bastion-01"
    assert mapped.extra["destination_host"] == "bastion-01"
    assert mapped.extra["service"] == "ssh"
    assert mapped.extra["auth_method"] == "publickey"


def test_windows_mapping_adds_user_host_process_and_service() -> None:
    event = _event(
        source="windows",
        actor="198.51.100.20",
        target="alice",
        action="windows_login",
        extra={
            "computer": "dc01.example.test",
            "process_name": r"C:\Windows\System32\winlogon.exe",
            "event_id": 4624,
        },
    )

    mapped = map_event_fields(event)

    assert mapped.extra["src_ip"] == "198.51.100.20"
    assert mapped.extra["user"] == "alice"
    assert mapped.extra["host"] == "dc01.example.test"
    assert mapped.extra["destination_host"] == "dc01.example.test"
    assert mapped.extra["process"] == r"C:\Windows\System32\winlogon.exe"
    assert mapped.extra["service"] == "windows-auth"
    assert mapped.extra["event_id"] == 4624


def test_nginx_mapping_adds_remote_user_and_http_aliases() -> None:
    event = _event(
        source="nginx",
        actor="192.0.2.30",
        target="/login",
        action="http_request",
        extra={"remote_user": "bob", "method": "POST", "status": 401},
    )

    mapped = map_event_fields(event)

    assert mapped.extra["src_ip"] == "192.0.2.30"
    assert mapped.extra["user"] == "bob"
    assert mapped.extra["service"] == "http"
    assert mapped.extra["http_method"] == "POST"
    assert mapped.extra["http_status"] == 401
    assert "destination_host" not in mapped.extra


def test_okta_mapping_adds_user_application_and_service() -> None:
    event = _event(
        source="okta",
        actor="203.0.113.40",
        target="Salesforce",
        action="okta_sso",
        extra={"user": "carol@example.test", "target_app": "Salesforce"},
    )

    mapped = map_event_fields(event)

    assert mapped.extra["src_ip"] == "203.0.113.40"
    assert mapped.extra["user"] == "carol@example.test"
    assert mapped.extra["application"] == "Salesforce"
    assert mapped.extra["service"] == "okta"


def test_explicit_upstream_canonical_field_wins() -> None:
    event = _event(
        source="nginx",
        actor="192.0.2.50",
        target="/",
        extra={"remote_user": "derived-user", "user": "trusted-upstream-user"},
    )

    assert map_event_fields(event).extra["user"] == "trusted-upstream-user"


def test_mapping_preserves_unknown_extra_and_original_event() -> None:
    event = _event(
        source="sshd",
        actor="192.0.2.60",
        target="root",
        extra={"vendor_extension": {"risk": 7}},
    )

    mapped = map_event_fields(event)

    assert mapped is not event
    assert event.extra == {"vendor_extension": {"risk": 7}}
    assert mapped.extra["vendor_extension"] == {"risk": 7}


def test_mapping_is_idempotent() -> None:
    event = _event(
        source="okta",
        actor="192.0.2.70",
        target="dana@example.test",
        extra={"user": "dana@example.test"},
    )

    once = map_event_fields(event)
    twice = map_event_fields(once)

    assert twice == once


def test_mapping_does_not_invent_geo_or_credential_enrichment() -> None:
    mapped = map_event_fields(
        _event(source="okta", actor="192.0.2.80", target="erin@example.test")
    )

    assert "continent" not in mapped.extra
    assert "password_hash" not in mapped.extra
    assert "credential_hash" not in mapped.extra
    assert "password_fingerprint" not in mapped.extra


def test_map_events_accepts_iterables_and_keeps_order() -> None:
    events = (
        _event(source="sshd", actor="192.0.2.1", target="first"),
        _event(source="sshd", actor="192.0.2.2", target="second"),
    )

    mapped = map_events(iter(events))

    assert [event.extra["user"] for event in mapped] == ["first", "second"]


def test_default_pipeline_is_stateless() -> None:
    event = _event(source="sshd", actor="192.0.2.90", target="root")

    assert DEFAULT_FIELD_MAPPING.map_event(event) == map_event_fields(event)
    assert DEFAULT_FIELD_MAPPING.map_events([event]) == map_events([event])


def test_detect_patterns_uses_mapping_before_lateral_movement_rule() -> None:
    events = [
        NormalizedEvent(
            ts=NOW + timedelta(seconds=index),
            actor="198.51.100.90",
            action="rdp_login",
            target="operator",
            result="success",
            source="windows",
            extra={"computer": f"host-{index}"},
        )
        for index in range(3)
    ]

    findings = detect_patterns(events)

    lateral = [
        finding
        for finding in findings
        if finding.metadata["rule_id"] == "001.mitre.t1021.lateral-movement"
    ]
    assert len(lateral) == 1
    assert lateral[0].metadata["targets"] == ["host-0", "host-1", "host-2"]
