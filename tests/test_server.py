"""Tests for the FastAPI webhook server."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from ai_soc_agent.config import MAX_RULE_WINDOW_SECONDS
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.server import API_TOKEN_ENV, _correlation_slice, create_app


def _fixture_payload() -> dict:
    path = Path(__file__).parents[1] / "samples" / "multi_source_demo.log"
    return json.loads(path.read_text(encoding="utf-8"))


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_ingest_batch_creates_and_lists_alerts():
    app = create_app()

    ingest_response = _request(app, "POST", "/ingest", json=_fixture_payload())
    alerts_response = _request(app, "GET", "/alerts")

    assert ingest_response.status_code == 202
    assert ingest_response.json()["accepted"] == 13
    assert ingest_response.json()["alerts_created"] == 2
    assert alerts_response.status_code == 200
    assert alerts_response.json()["count"] == 2
    assert [item["type"] for item in alerts_response.json()["alerts"]] == [
        "brute_force",
        "credential_stuffing",
    ]


def test_ingest_splunk_envelope_accepts_single_event():
    app = create_app()
    event = _fixture_payload()["events"][0]

    response = _request(app, "POST", "/ingest", json={"event": event})

    assert response.status_code == 202
    assert response.json() == {
        "accepted": 1,
        "alerts_created": 0,
        "alert_ids": [],
        "total_alerts": 0,
    }


def test_ingest_rejects_invalid_result_and_empty_batch():
    app = create_app()
    event = {**_fixture_payload()["events"][0], "result": "denied"}

    invalid = _request(app, "POST", "/ingest", json=event)
    empty = _request(app, "POST", "/ingest", json={"events": []})

    assert invalid.status_code == 422
    assert empty.status_code == 400


def test_alerts_support_type_filter():
    app = create_app()
    _request(app, "POST", "/ingest", json=_fixture_payload())

    response = _request(
        app,
        "GET",
        "/alerts",
        params={"type": "credential_stuffing", "limit": 1},
    )

    assert response.status_code == 200
    assert response.json()["count"] == 1
    assert response.json()["alerts"][0]["type"] == "credential_stuffing"


def test_create_app_isolates_state_and_enforces_batch_limit():
    populated = create_app()
    isolated = create_app(max_events=2)
    _request(
        populated,
        "POST",
        "/ingest",
        json={"event": _fixture_payload()["events"][0]},
    )

    assert _request(isolated, "GET", "/alerts").json() == {"count": 0, "alerts": []}
    response = _request(isolated, "POST", "/ingest", json=_fixture_payload())
    assert response.status_code == 413


def test_repeated_ingest_does_not_duplicate_one_incident():
    """Alert ids used to be hashed from window bounds, so replays piled up."""
    app = create_app()
    payload = _fixture_payload()

    first = _request(app, "POST", "/ingest", json=payload)
    second = _request(app, "POST", "/ingest", json=payload)

    assert first.json()["alerts_created"] == 2
    assert second.json()["alerts_created"] == 0
    assert second.json()["total_alerts"] == 2
    assert _request(app, "GET", "/alerts").json()["count"] == 2


def test_repeated_ingest_widens_the_stored_alert():
    app = create_app()
    payload = _fixture_payload()
    _request(app, "POST", "/ingest", json=payload)
    _request(app, "POST", "/ingest", json=payload)

    alerts = _request(app, "GET", "/alerts", params={"type": "brute_force"}).json()
    alert = alerts["alerts"][0]

    assert alert["event_count"] >= 10
    assert alert["first_seen"] <= alert["last_seen"]


def test_health_is_unauthenticated_and_reports_counters():
    app = create_app(api_token="s3cret")

    response = _request(app, "GET", "/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["auth_required"] is True
    assert body["events"] == 0
    assert body["alerts"] == 0


def test_endpoints_require_bearer_token_when_configured():
    app = create_app(api_token="s3cret")
    payload = _fixture_payload()

    anonymous = _request(app, "POST", "/ingest", json=payload)
    wrong = _request(
        app, "GET", "/alerts", headers={"Authorization": "Bearer nope"}
    )
    authorized = _request(
        app, "POST", "/ingest", json=payload, headers={"Authorization": "Bearer s3cret"}
    )

    assert anonymous.status_code == 401
    assert wrong.status_code == 401
    assert authorized.status_code == 202


def test_endpoints_stay_open_when_no_token_is_configured(monkeypatch):
    monkeypatch.delenv(API_TOKEN_ENV, raising=False)
    app = create_app()

    assert _request(app, "GET", "/alerts").status_code == 200
    assert _request(app, "GET", "/health").json()["auth_required"] is False


def test_token_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv(API_TOKEN_ENV, "from-env")
    app = create_app()

    assert _request(app, "GET", "/alerts").status_code == 401
    assert (
        _request(
            app, "GET", "/alerts", headers={"Authorization": "Bearer from-env"}
        ).status_code
        == 200
    )


def _event(ts: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        ts=ts,
        actor="203.0.113.45",
        action="login",
        target="root",
        result="failure",
        source="sshd",
    )


def test_correlation_slice_drops_history_no_rule_can_match():
    newest = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    stale = newest - timedelta(seconds=MAX_RULE_WINDOW_SECONDS + 1)
    inside = newest - timedelta(seconds=MAX_RULE_WINDOW_SECONDS - 1)

    kept = _correlation_slice([_event(stale), _event(inside), _event(newest)])

    assert [event.ts for event in kept] == [inside, newest]


def test_correlation_slice_tolerates_naive_timestamps():
    naive = datetime(2026, 7, 24, 12, 0)
    aware = datetime(2026, 7, 24, 12, 0, 30, tzinfo=UTC)

    assert len(_correlation_slice([_event(naive), _event(aware)])) == 2


def test_correlation_slice_of_empty_store_is_empty():
    assert _correlation_slice([]) == []
