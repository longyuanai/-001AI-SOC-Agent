"""Bounded cross-batch state tests for STATE-001."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from ai_soc_agent.cli import scan_payload
from ai_soc_agent.config import DetectionConfig
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.server import create_app
from ai_soc_agent.state import WindowStateStore

NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)


def _event(
    seconds: int,
    *,
    actor: str = "203.0.113.30",
    target: str = "root",
) -> NormalizedEvent:
    return NormalizedEvent(
        ts=NOW + timedelta(seconds=seconds),
        actor=actor,
        action="ssh_login",
        target=target,
        result="failure",
        source="sshd",
        raw=f"event-{seconds}-{actor}-{target}",
    )


def _payload(event: NormalizedEvent) -> dict:
    return {
        "ts": event.ts.isoformat(),
        "actor": event.actor,
        "action": event.action,
        "target": event.target,
        "result": event.result,
        "source": event.source,
        "raw": event.raw,
        "extra": event.extra,
    }


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_state_rejects_non_positive_limits() -> None:
    with pytest.raises(ValueError, match="max_events"):
        WindowStateStore(max_events=0)
    with pytest.raises(ValueError, match="horizon"):
        WindowStateStore(horizon=timedelta(0))


def test_state_snapshot_is_event_time_ordered() -> None:
    state = WindowStateStore()

    state.append([_event(2), _event(0), _event(1)])

    assert [event.ts for event in state.snapshot()] == [
        NOW,
        NOW + timedelta(seconds=1),
        NOW + timedelta(seconds=2),
    ]


def test_state_accumulates_across_append_calls() -> None:
    state = WindowStateStore()

    state.append([_event(0)])
    state.append([_event(1)])

    assert len(state) == 2
    assert len(state.snapshot()) == 2


def test_state_ignores_exact_duplicate_event() -> None:
    state = WindowStateStore()
    event = _event(0)

    first = state.append([event])
    second = state.append([event])

    assert first.accepted == 1
    assert second.accepted == 0
    assert second.duplicates == 1
    assert len(state) == 1


def test_state_evicts_events_outside_event_time_horizon() -> None:
    state = WindowStateStore(horizon=timedelta(minutes=5))

    state.append([_event(0), _event(301)])

    assert state.snapshot() == [_event(301)]


def test_state_rejects_late_event_older_than_watermark_horizon() -> None:
    state = WindowStateStore(horizon=timedelta(minutes=5))
    state.append([_event(600)])

    result = state.append([_event(0)])

    assert result.expired == 1
    assert state.snapshot() == [_event(600)]


def test_state_capacity_evicts_oldest_event_time() -> None:
    state = WindowStateStore(max_events=2)

    result = state.append([_event(2), _event(0), _event(1)])

    assert result.evicted == 1
    assert state.snapshot() == [_event(1), _event(2)]


def test_state_namespaces_do_not_mix() -> None:
    state = WindowStateStore()

    state.append([_event(0, target="alice")], namespace="tenant-a")
    state.append([_event(1, target="bob")], namespace="tenant-b")

    assert [event.target for event in state.snapshot("tenant-a")] == ["alice"]
    assert [event.target for event in state.snapshot("tenant-b")] == ["bob"]
    assert state.namespaces() == ("tenant-a", "tenant-b")


def test_state_injected_clock_prunes_idle_history() -> None:
    state = WindowStateStore(
        horizon=timedelta(hours=1),
        clock=lambda: NOW + timedelta(hours=2),
    )
    state.append([_event(0)])

    evicted = state.prune_expired()

    assert evicted == 1
    assert len(state) == 0


def test_state_snapshot_limit_returns_most_recent_events() -> None:
    state = WindowStateStore()
    state.append([_event(index) for index in range(5)])

    assert state.snapshot(limit=2) == [_event(3), _event(4)]
    with pytest.raises(ValueError, match="limit"):
        state.snapshot(limit=0)


def test_server_correlates_brute_force_across_requests() -> None:
    app = create_app(
        config=DetectionConfig(
            brute_force_threshold=3,
            brute_force_window_seconds=60,
        )
    )

    first = _request(app, "POST", "/ingest", json=_payload(_event(0)))
    second = _request(app, "POST", "/ingest", json=_payload(_event(1)))
    third = _request(app, "POST", "/ingest", json=_payload(_event(2)))

    assert first.json()["alerts_created"] == 0
    assert second.json()["alerts_created"] == 0
    assert third.json()["alerts_created"] == 1


def test_server_duplicate_webhook_does_not_inflate_window() -> None:
    app = create_app(
        config=DetectionConfig(
            brute_force_threshold=3,
            brute_force_window_seconds=60,
        )
    )
    first_event = _payload(_event(0))

    _request(app, "POST", "/ingest", json=first_event)
    _request(app, "POST", "/ingest", json=first_event)
    response = _request(app, "POST", "/ingest", json=_payload(_event(1)))

    assert response.json()["alerts_created"] == 0
    assert _request(app, "GET", "/health").json()["events"] == 2


def test_scan_payload_remains_stateless_between_calls() -> None:
    payload = {
        "source": "sshd",
        "brute_force_threshold": 3,
        "events": [_payload(_event(0)), _payload(_event(1))],
    }

    assert scan_payload(payload) == {"findings": []}
    assert scan_payload(payload) == {"findings": []}
