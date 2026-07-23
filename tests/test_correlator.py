"""Tests for deterministic event-correlation rules."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ai_soc_agent.correlator import detect_brute_force
from ai_soc_agent.normalizer import NormalizedEvent


def _event(
    ts: datetime,
    *,
    actor: str = "203.0.113.45",
    target: str = "admin",
    result: str = "failure",
    source: str = "sshd",
) -> NormalizedEvent:
    return NormalizedEvent(
        ts=ts,
        actor=actor,
        action="login",
        target=target,
        result=result,
        source=source,
    )


def test_brute_force_alert_at_ten_failures_within_five_minutes():
    start = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)
    events = [_event(start + timedelta(seconds=30 * index)) for index in range(10)]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.kind == "brute_force"
    assert alert.actor == "203.0.113.45"
    assert alert.event_count == 10
    assert alert.severity == "high"
    assert alert.sources == ("sshd",)
    assert alert.to_dict()["type"] == "brute_force"


def test_brute_force_does_not_fire_outside_window():
    start = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)
    events = [_event(start + timedelta(minutes=index)) for index in range(10)]

    assert detect_brute_force(events) == []


def test_brute_force_groups_by_ip_and_ignores_successes():
    start = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)
    events = [
        *[_event(start + timedelta(seconds=index), actor="203.0.113.45") for index in range(5)],
        *[_event(start + timedelta(seconds=index), actor="198.51.100.20") for index in range(5)],
        *[
            _event(start + timedelta(seconds=index), actor="203.0.113.45", result="success")
            for index in range(10)
        ],
    ]

    assert detect_brute_force(events) == []


def test_brute_force_handles_unsorted_mixed_timezone_events():
    start_naive = datetime(2026, 7, 24, 1, 0)
    events = [_event(start_naive + timedelta(seconds=20 * index)) for index in range(5)]
    events += [
        _event(
            datetime(2026, 7, 24, 1, 2, tzinfo=UTC) + timedelta(seconds=20 * index),
            source="nginx",
        )
        for index in range(5)
    ]

    alerts = detect_brute_force(list(reversed(events)))

    assert len(alerts) == 1
    assert alerts[0].sources == ("nginx", "sshd")


def test_brute_force_validates_configuration():
    with pytest.raises(ValueError, match="window"):
        detect_brute_force([], window=timedelta())
    with pytest.raises(ValueError, match="threshold"):
        detect_brute_force([], threshold=0)
