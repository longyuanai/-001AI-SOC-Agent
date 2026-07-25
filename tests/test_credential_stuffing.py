"""Tests for both credential-stuffing modes, through the live rule engine."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ai_soc_agent.config import CROSS_SOURCE_MODE
from ai_soc_agent.correlator import correlate, detect_patterns, finding_to_alert
from ai_soc_agent.normalizer import NormalizedEvent


def _event(
    offset_minutes: int,
    *,
    source: str,
    user: str = "victim@example.test",
    actor: str = "198.51.100.20",
    result: str = "failure",
    extra: dict | None = None,
) -> NormalizedEvent:
    target = "/login" if source == "nginx" else user
    return NormalizedEvent(
        ts=datetime(2026, 7, 24, 1, offset_minutes, tzinfo=UTC),
        actor=actor,
        action="login",
        target=target,
        result=result,
        source=source,
        extra=extra if extra is not None else {},
    )


def _cross_source_alerts(events: list[NormalizedEvent]):
    return [
        alert for alert in correlate(events) if alert.kind == "credential_stuffing"
    ]


def test_credential_stuffing_requires_ssh_vpn_and_web():
    events = [
        _event(0, source="sshd"),
        _event(1, source="vpn"),
        _event(2, source="nginx", extra={"remote_user": "victim@example.test"}),
    ]

    alerts = _cross_source_alerts(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.kind == "credential_stuffing"
    assert alert.actor == "victim@example.test"
    assert alert.targets == ("victim@example.test",)
    assert alert.sources == ("nginx", "sshd", "vpn")
    assert alert.event_count == 3


def test_credential_stuffing_does_not_fire_for_two_source_families():
    events = [
        _event(0, source="sshd"),
        _event(1, source="vpn"),
        _event(2, source="vpn"),
    ]

    assert _cross_source_alerts(events) == []


def test_credential_stuffing_groups_by_normalized_user():
    events = [
        _event(0, source="sshd", user="Victim@Example.Test"),
        _event(1, source="vpn", user="victim@example.test"),
        _event(2, source="okta", extra={"user": "VICTIM@example.test"}),
    ]

    alerts = _cross_source_alerts(events)

    assert len(alerts) == 1
    assert alerts[0].actor == "victim@example.test"


def test_credential_stuffing_respects_time_window_and_user():
    events = [
        _event(0, source="sshd"),
        _event(1, source="vpn"),
        _event(12, source="nginx", extra={"remote_user": "victim@example.test"}),
        _event(
            2,
            source="nginx",
            user="other@example.test",
            extra={"remote_user": "other@example.test"},
        ),
    ]

    assert _cross_source_alerts(events) == []


def test_credential_stuffing_reports_each_targeted_account():
    events = [
        *[
            _event(index, source=source, user="victim-a@example.test")
            for index, source in enumerate(("sshd", "vpn", "okta"))
        ],
        *[
            _event(index, source=source, user="victim-b@example.test")
            for index, source in enumerate(("sshd", "vpn", "okta"))
        ],
    ]

    alerts = _cross_source_alerts(events)

    assert sorted(alert.actor for alert in alerts) == [
        "victim-a@example.test",
        "victim-b@example.test",
    ]


def test_per_credential_mode_detects_one_password_across_accounts():
    """The default (non-streaming) mode groups by credential fingerprint."""
    events = [
        _event(
            index,
            source="nginx",
            user=user,
            actor="203.0.113.77",
            extra={"user": user, "password_hash": "sha256:reused-demo"},
        )
        for index, user in enumerate(("alice", "bob", "carol"))
    ]

    findings = detect_patterns(events)
    alerts = [
        finding_to_alert(finding)
        for finding in findings
        if finding.metadata["alert_kind"] == "credential_stuffing"
    ]

    assert len(alerts) == 1
    assert alerts[0].actor == "203.0.113.77"
    assert alerts[0].targets == ("alice", "bob", "carol")
    assert findings[0].metadata["credential_fingerprint"] == "sha256:reused-demo"


def test_per_credential_mode_is_not_used_by_the_streaming_profile():
    events = [
        _event(
            index,
            source="nginx",
            user=user,
            actor="203.0.113.77",
            extra={"user": user, "password_hash": "sha256:reused-demo"},
        )
        for index, user in enumerate(("alice", "bob", "carol"))
    ]

    assert detect_patterns(events, facts={"credential_stuffing_mode": CROSS_SOURCE_MODE}) == []


def test_multi_source_fixture_triggers_both_rules():
    fixture_path = Path(__file__).parents[1] / "samples" / "multi_source_demo.log"
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))
    events = [
        NormalizedEvent(
            ts=datetime.fromisoformat(item["ts"].replace("Z", "+00:00")),
            actor=item["actor"],
            action=item["action"],
            target=item["target"],
            result=item["result"],
            source=item["source"],
            extra=item["extra"],
        )
        for item in payload["events"]
    ]

    alerts = correlate(events)

    assert [alert.kind for alert in alerts] == ["brute_force", "credential_stuffing"]


def test_window_boundary_is_exclusive_beyond_ten_minutes():
    events = [
        _event(0, source="sshd"),
        _event(5, source="vpn"),
        _event(11, source="okta"),
    ]

    assert _cross_source_alerts(events) == []
    assert len(_cross_source_alerts([*events[:2], _event(10, source="okta")])) == 1


def test_successful_logins_never_produce_a_stuffing_alert():
    events = [
        _event(index, source=source, result="success")
        for index, source in enumerate(("sshd", "vpn", "okta"))
    ]

    assert _cross_source_alerts(events) == []
