"""Tests for cross-source credential-stuffing correlation."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ai_soc_agent.correlator import correlate, detect_credential_stuffing
from ai_soc_agent.normalizer import NormalizedEvent


def _event(
    offset_minutes: int,
    *,
    source: str,
    user: str = "victim@example.test",
    actor: str = "198.51.100.20",
    extra: dict | None = None,
) -> NormalizedEvent:
    target = "/login" if source == "nginx" else user
    return NormalizedEvent(
        ts=datetime(2026, 7, 24, 1, offset_minutes, tzinfo=UTC),
        actor=actor,
        action="login",
        target=target,
        result="failure",
        source=source,
        extra=extra if extra is not None else {},
    )


def test_credential_stuffing_requires_ssh_vpn_and_web():
    events = [
        _event(0, source="sshd"),
        _event(1, source="vpn"),
        _event(2, source="nginx", extra={"remote_user": "victim@example.test"}),
    ]

    alerts = detect_credential_stuffing(events)

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

    assert detect_credential_stuffing(events) == []


def test_credential_stuffing_groups_by_normalized_user():
    events = [
        _event(0, source="sshd", user="Victim@Example.Test"),
        _event(1, source="vpn", user="victim@example.test"),
        _event(2, source="okta", extra={"user": "VICTIM@example.test"}),
    ]

    alerts = detect_credential_stuffing(events)

    assert len(alerts) == 1
    assert alerts[0].actor == "victim@example.test"


def test_credential_stuffing_respects_time_window_and_user():
    events = [
        _event(0, source="sshd"),
        _event(1, source="vpn"),
        _event(12, source="nginx", extra={"remote_user": "victim@example.test"}),
        _event(2, source="nginx", user="other@example.test", extra={"remote_user": "other@example.test"}),
    ]

    assert detect_credential_stuffing(events, window=timedelta(minutes=10)) == []


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
