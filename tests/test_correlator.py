"""Tests for the Alert projection exposed by the /alerts API.

These exercise ``correlate()`` — the code path the API actually runs. The old
suite tested ``detect_brute_force``/``detect_credential_stuffing``, which no
caller invoked any more, so regressions in the live pipeline went unnoticed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource

from ai_soc_agent.correlator import correlate, detect_patterns, finding_to_alert
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.parsers import parse_nginx_line

START = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)


def _event(
    ts: datetime,
    *,
    actor: str = "203.0.113.45",
    action: str = "login",
    target: str = "admin",
    result: str = "failure",
    source: str = "sshd",
    extra: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        ts=ts,
        actor=actor,
        action=action,
        target=target,
        result=result,
        source=source,
        extra=extra or {},
    )


def _burst(actor: str, *, count: int = 10, step: int = 30) -> list[NormalizedEvent]:
    return [
        _event(START + timedelta(seconds=step * index), actor=actor)
        for index in range(count)
    ]


def test_brute_force_alert_at_ten_failures_within_five_minutes():
    alerts = correlate(_burst("203.0.113.45"))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.kind == "brute_force"
    assert alert.actor == "203.0.113.45"
    assert alert.event_count == 10
    assert alert.severity == "high"
    assert alert.sources == ("sshd",)
    assert alert.to_dict()["type"] == "brute_force"


def test_brute_force_does_not_fire_outside_window():
    events = [_event(START + timedelta(minutes=index)) for index in range(10)]

    assert correlate(events) == []


def test_brute_force_ignores_successes_and_sub_threshold_actors():
    events = [
        *_burst("203.0.113.45", count=5),
        *_burst("198.51.100.20", count=5),
        *[
            _event(START + timedelta(seconds=index), result="success")
            for index in range(10)
        ],
    ]

    assert correlate(events) == []


def test_brute_force_reports_every_offending_ip_not_just_the_first():
    events = [*_burst("203.0.113.45"), *_burst("198.51.100.20")]

    alerts = correlate(events)

    assert [alert.kind for alert in alerts] == ["brute_force", "brute_force"]
    assert sorted(alert.actor for alert in alerts) == [
        "198.51.100.20",
        "203.0.113.45",
    ]


def test_brute_force_handles_unsorted_mixed_timezone_events():
    naive = [
        _event(datetime(2026, 7, 24, 1, 0) + timedelta(seconds=20 * index))
        for index in range(5)
    ]
    aware = [
        _event(
            datetime(2026, 7, 24, 1, 2, tzinfo=UTC) + timedelta(seconds=20 * index),
            source="nginx",
        )
        for index in range(5)
    ]

    alerts = correlate(list(reversed(naive + aware)))

    assert len(alerts) == 1
    assert alerts[0].sources == ("nginx", "sshd")


def test_alert_id_is_stable_as_the_incident_accumulates_events():
    """Re-correlating a growing stream must not mint a new id per ingest."""
    first = correlate(_burst("203.0.113.45"))
    second = correlate(_burst("203.0.113.45", count=14))
    trimmed = correlate(_burst("203.0.113.45", count=10, step=20))

    assert first[0].id == second[0].id == trimmed[0].id
    assert first[0].last_seen != trimmed[0].last_seen


def test_alert_ids_differ_per_actor():
    alerts = correlate([*_burst("203.0.113.45"), *_burst("198.51.100.20")])

    assert len({alert.id for alert in alerts}) == 2


def _priv_esc_events() -> list[NormalizedEvent]:
    return [
        _event(
            START + timedelta(seconds=30 * index),
            actor="deploy",
            action="sudo_exec",
            target="root",
            source="linux-audit",
            extra={"user": "deploy", "host": "10.0.0.15", "process": "sudo"},
        )
        for index in range(3)
    ]


def _geo_events() -> list[NormalizedEvent]:
    return [
        _event(
            START,
            actor="198.51.100.10",
            action="okta_login",
            target="analyst@example.test",
            result="success",
            source="okta",
            extra={"user": "analyst@example.test", "continent": "NA"},
        ),
        _event(
            START + timedelta(minutes=30),
            actor="198.51.100.20",
            action="okta_login",
            target="analyst@example.test",
            result="success",
            source="okta",
            extra={"user": "analyst@example.test", "continent": "EU"},
        ),
    ]


def _lateral_events() -> list[NormalizedEvent]:
    return [
        _event(
            START + timedelta(minutes=index),
            actor="operator",
            action="ssh_login",
            target=host,
            result="success",
            source="sshd",
            extra={"user": "operator", "destination_host": host},
        )
        for index, host in enumerate(("db-1", "desktop-2", "app-3"))
    ]


def _cross_source_events() -> list[NormalizedEvent]:
    return [
        _event(START, actor="198.51.100.1", target="victim@example.test"),
        _event(
            START + timedelta(minutes=1),
            actor="198.51.100.2",
            action="vpn_login",
            target="victim@example.test",
            source="vpn",
        ),
        _event(
            START + timedelta(minutes=2),
            actor="198.51.100.3",
            action="http_request",
            target="/login",
            source="nginx",
            extra={"remote_user": "victim@example.test"},
        ),
    ]


def test_all_five_pattern_kinds_reach_the_alerts_projection():
    """Three of five patterns used to be dropped for lacking alert metadata."""
    events = [
        *_burst("203.0.113.45"),
        *_priv_esc_events(),
        *_geo_events(),
        *_lateral_events(),
        *_cross_source_events(),
    ]

    kinds = {alert.kind for alert in correlate(events)}

    assert kinds == {
        "brute_force",
        "privilege_escalation",
        "geo_anomaly",
        "lateral_movement",
        "credential_stuffing",
    }


def test_privilege_escalation_alert_carries_actor_and_window():
    alerts = correlate(_priv_esc_events())

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.kind == "privilege_escalation"
    assert alert.actor == "deploy"
    assert alert.event_count == 3
    assert alert.first_seen < alert.last_seen


def test_lateral_movement_alert_lists_reached_hosts():
    alerts = correlate(_lateral_events())

    assert len(alerts) == 1
    assert alerts[0].kind == "lateral_movement"
    assert alerts[0].targets == ("app-3", "db-1", "desktop-2")


def test_geo_anomaly_alert_names_the_account():
    alerts = correlate(_geo_events())

    assert len(alerts) == 1
    assert alerts[0].kind == "geo_anomaly"
    assert alerts[0].actor == "analyst@example.test"


def test_finding_without_alert_metadata_degrades_instead_of_disappearing():
    finding = Finding(
        id="",
        source=FindingSource.SOC,
        severity=FindingSeverity.HIGH,
        confidence=0.5,
        title="bare finding",
        description="no alert metadata at all",
        host="10.0.0.9",
        ts=START,
        evidence=("line-a", "line-b"),
        tags=frozenset(),
        metadata={"rule_id": "001.custom.rule"},
    )

    alert = finding_to_alert(finding)

    assert alert.kind == "001.custom.rule"
    assert alert.actor == "10.0.0.9"
    assert alert.event_count == 2
    assert alert.first_seen == START


def _nginx_login_failures(ip: str, count: int = 5) -> list[NormalizedEvent]:
    return [
        parse_nginx_line(
            f'{ip} - - [24/Jul/2026:09:15:{index:02d} +0800] '
            f'"POST /login HTTP/1.1" 401 97 "-" "curl/8"'
        )
        for index in range(count)
    ]


def test_web_login_brute_force_is_detected_end_to_end():
    """nginx events were all action=http_request, so T1110 never saw them."""
    findings = detect_patterns(_nginx_login_failures("203.0.113.45"))

    assert len(findings) == 1
    assert findings[0].metadata["alert_kind"] == "brute_force"
    assert findings[0].host == "203.0.113.45"


def test_browsing_a_site_is_not_a_web_brute_force():
    events = [
        parse_nginx_line(
            f'203.0.113.45 - - [24/Jul/2026:09:15:{index:02d} +0800] '
            f'"GET /login HTTP/1.1" 200 1842 "-" "Mozilla/5.0"'
        )
        for index in range(10)
    ]

    assert detect_patterns(events) == []


def test_web_brute_force_reports_each_source_ip():
    events = [
        *_nginx_login_failures("203.0.113.45"),
        *_nginx_login_failures("198.51.100.20"),
    ]

    findings = detect_patterns(events)

    assert sorted(finding.host for finding in findings) == [
        "198.51.100.20",
        "203.0.113.45",
    ]
