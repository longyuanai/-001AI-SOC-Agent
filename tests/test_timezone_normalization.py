"""Regression tests for mixed naive/aware timestamps across log sources.

sshd carries no offset while evtx/nginx/okta do. Before normalization landed,
one mixed batch made ``detect_patterns`` raise
``TypeError: can't compare offset-naive and offset-aware datetimes``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta, timezone

from ai_soc_agent.adapter import SOCProductAdapter
from ai_soc_agent.correlator import correlate, detect_patterns
from ai_soc_agent.normalizer import NormalizedEvent, ensure_utc
from ai_soc_agent.server import create_app
from tests.test_server import _request


def _event(ts: datetime, *, source: str = "sshd", actor: str = "203.0.113.45") -> NormalizedEvent:
    return NormalizedEvent(
        ts=ts,
        actor=actor,
        action="login",
        target="root",
        result="failure",
        source=source,
    )


def test_normalized_event_pins_naive_timestamps_to_utc() -> None:
    event = _event(datetime(2026, 7, 24, 1, 0))

    assert event.ts.tzinfo is not None
    assert event.ts == datetime(2026, 7, 24, 1, 0, tzinfo=UTC)


def test_normalized_event_converts_offsets_to_utc() -> None:
    event = _event(datetime(2026, 7, 24, 9, 0, tzinfo=timezone(timedelta(hours=8))))

    assert event.ts == datetime(2026, 7, 24, 1, 0, tzinfo=UTC)


def test_ensure_utc_is_idempotent() -> None:
    once = ensure_utc(datetime(2026, 7, 24, 1, 0))

    assert ensure_utc(once) == once


def test_detect_patterns_survives_mixed_awareness() -> None:
    events = [
        _event(datetime(2026, 7, 24, 1, 0) + timedelta(seconds=10 * index))
        for index in range(3)
    ]
    events += [
        _event(
            datetime(2026, 7, 24, 1, 0, tzinfo=UTC) + timedelta(seconds=10 * index),
            source="nginx",
        )
        for index in range(3, 6)
    ]

    findings = detect_patterns(events, facts={"brute_force_threshold": 5})

    assert len(findings) == 1
    assert findings[0].metadata["rule_id"] == "001.mitre.t1110.brute-force-burst"


def test_correlate_survives_mixed_awareness() -> None:
    events = [
        _event(datetime(2026, 7, 24, 1, 0) + timedelta(seconds=20 * index))
        for index in range(5)
    ]
    events += [
        _event(
            datetime(2026, 7, 24, 1, 2, tzinfo=UTC) + timedelta(seconds=20 * index),
            source="nginx",
        )
        for index in range(5)
    ]

    alerts = correlate(events)

    assert [alert.kind for alert in alerts] == ["brute_force"]
    assert alerts[0].sources == ("nginx", "sshd")


def test_ingest_accepts_batch_mixing_naive_and_offset_timestamps() -> None:
    app = create_app()
    payload = {
        "events": [
            {
                # no offset — an ELK shipper forwarding raw syslog
                "ts": "2026-07-24T01:00:00",
                "actor": "203.0.113.45",
                "action": "ssh_login",
                "target": "root",
                "result": "failure",
                "source": "sshd",
            },
            {
                # offset present — the same attacker hitting the web tier
                "ts": "2026-07-24T09:00:30+08:00",
                "actor": "203.0.113.45",
                "action": "http_request",
                "target": "/login",
                "result": "failure",
                "source": "nginx",
            },
        ]
    }

    response = _request(app, "POST", "/ingest", json=payload)

    assert response.status_code == 202
    assert response.json()["accepted"] == 2


def test_adapter_scan_survives_mixed_awareness() -> None:
    payload = {
        "source": "sshd",
        "brute_force_threshold": 2,
        "events": [
            {
                "ts": "2026-07-24T01:00:00",
                "actor": "203.0.113.45",
                "action": "ssh_login",
                "target": "root",
                "result": "failure",
                "source": "sshd",
            },
            {
                "ts": "2026-07-24T01:00:10+00:00",
                "actor": "203.0.113.45",
                "action": "ssh_login",
                "target": "root",
                "result": "failure",
                "source": "sshd",
            },
        ],
    }

    async def collect() -> list:
        return [finding async for finding in SOCProductAdapter().scan(payload)]

    findings = asyncio.run(collect())

    assert len(findings) == 1
    assert findings[0].host == "203.0.113.45"
