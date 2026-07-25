"""Tests for the FastAPI webhook server."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx

from ai_soc_agent.server import create_app


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
    assert alerts_response.json()["total"] == 2
    # Most recent first: credential stuffing ends at 01:07, brute force at 01:03.
    assert [item["type"] for item in alerts_response.json()["alerts"]] == [
        "credential_stuffing",
        "brute_force",
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

    assert _request(isolated, "GET", "/alerts").json() == {
        "count": 0,
        "total": 0,
        "alerts": [],
    }
    response = _request(isolated, "POST", "/ingest", json=_fixture_payload())
    assert response.status_code == 413
