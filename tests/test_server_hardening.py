"""Server behavior that keeps a long-running deployment healthy.

Covers the alert-store leak (ids hashed first_seen/last_seen, so a sustained
attack minted a new alert per ingest), the unauthenticated write path, and the
absent liveness route.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ai_soc_agent.server import create_app
from tests.test_server import _request

START = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)


def _failure(offset_seconds: int, *, actor: str = "203.0.113.45") -> dict:
    return {
        "ts": (START + timedelta(seconds=offset_seconds)).isoformat(),
        "actor": actor,
        "action": "ssh_login",
        "target": "root",
        "result": "failure",
        "source": "sshd",
    }


def _burst(start: int, count: int, *, actor: str = "203.0.113.45") -> dict:
    return {"events": [_failure(start + index * 10, actor=actor) for index in range(count)]}


def test_sustained_attack_updates_one_alert_instead_of_accumulating() -> None:
    app = create_app()

    first = _request(app, "POST", "/ingest", json=_burst(0, 12))
    second = _request(app, "POST", "/ingest", json=_burst(120, 12))
    third = _request(app, "POST", "/ingest", json=_burst(240, 12))

    assert first.json()["alerts_created"] == 1
    assert second.json()["alerts_created"] == 0
    assert third.json()["alerts_created"] == 0
    assert third.json()["total_alerts"] == 1

    alerts = _request(app, "GET", "/alerts").json()
    assert alerts["total"] == 1
    # The single alert absorbed the later evidence rather than being duplicated.
    assert alerts["alerts"][0]["event_count"] >= 12


def test_distinct_actors_still_get_distinct_alerts() -> None:
    app = create_app()

    _request(app, "POST", "/ingest", json=_burst(0, 12, actor="203.0.113.45"))
    response = _request(app, "POST", "/ingest", json=_burst(0, 12, actor="198.51.100.20"))

    assert response.json()["alerts_created"] == 1
    assert _request(app, "GET", "/alerts").json()["total"] == 2


def test_alert_store_is_capped() -> None:
    app = create_app(max_alerts=3)

    for index in range(6):
        _request(app, "POST", "/ingest", json=_burst(0, 12, actor=f"203.0.113.{index}"))

    assert _request(app, "GET", "/alerts").json()["total"] == 3


def test_health_reports_store_state_without_serializing_alerts() -> None:
    app = create_app()
    _request(app, "POST", "/ingest", json=_burst(0, 12))

    response = _request(app, "GET", "/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["product"] == "001-soc"
    assert body["events"] == 12
    assert body["alerts"] == 1


def test_ingest_requires_bearer_token_when_configured() -> None:
    app = create_app(api_token="s3cret")

    missing = _request(app, "POST", "/ingest", json=_burst(0, 12))
    wrong = _request(
        app,
        "POST",
        "/ingest",
        json=_burst(0, 12),
        headers={"Authorization": "Bearer nope"},
    )
    correct = _request(
        app,
        "POST",
        "/ingest",
        json=_burst(0, 12),
        headers={"Authorization": "Bearer s3cret"},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert correct.status_code == 202


def test_ingest_is_open_when_no_token_is_configured() -> None:
    app = create_app(api_token="")

    assert _request(app, "POST", "/ingest", json=_burst(0, 12)).status_code == 202


def test_oversized_body_is_rejected_before_buffering() -> None:
    app = create_app(max_request_bytes=256)

    response = _request(app, "POST", "/ingest", json=_burst(0, 100))

    assert response.status_code == 413


def test_alerts_support_offset_pagination() -> None:
    app = create_app()
    for index in range(3):
        _request(app, "POST", "/ingest", json=_burst(0, 12, actor=f"203.0.113.{index}"))

    first_page = _request(app, "GET", "/alerts", params={"limit": 2}).json()
    second_page = _request(app, "GET", "/alerts", params={"limit": 2, "offset": 2}).json()

    assert first_page["total"] == 3
    assert first_page["count"] == 2
    assert second_page["count"] == 1
    ids = {alert["id"] for alert in first_page["alerts"]}
    assert ids.isdisjoint({alert["id"] for alert in second_page["alerts"]})


def test_alerts_filter_by_severity() -> None:
    app = create_app()
    _request(app, "POST", "/ingest", json=_burst(0, 12))

    matching = _request(app, "GET", "/alerts", params={"severity": "high"}).json()
    missing = _request(app, "GET", "/alerts", params={"severity": "low"}).json()

    assert matching["total"] == 1
    assert missing["total"] == 0
