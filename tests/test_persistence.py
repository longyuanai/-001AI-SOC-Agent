"""PERSIST-001 bounded SQLite alert storage tests."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from ai_soc_agent.config import DetectionConfig
from ai_soc_agent.correlator import Alert
from ai_soc_agent.persistence import SQLiteAlertRepository, alert_identity
from ai_soc_agent.server import create_app

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _alert(
    actor: str = "203.0.113.10",
    *,
    seconds: int = 0,
    event_count: int = 5,
) -> Alert:
    return Alert(
        id=f"brute-force-{actor}-{seconds}",
        kind="brute_force",
        severity="high",
        actor=actor,
        targets=("root",),
        first_seen=NOW + timedelta(seconds=seconds),
        last_seen=NOW + timedelta(seconds=seconds + event_count - 1),
        event_count=event_count,
        sources=("sshd",),
        summary=f"{actor} produced failed events.",
    )


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def _event(seconds: int) -> dict:
    return {
        "ts": (NOW + timedelta(seconds=seconds)).isoformat(),
        "actor": "203.0.113.99",
        "action": "ssh_login",
        "target": "root",
        "result": "failure",
        "source": "sshd",
        "raw": f"sensitive raw event {seconds}",
        "extra": {},
    }


def test_repository_rejects_non_positive_capacity(tmp_path) -> None:
    with pytest.raises(ValueError, match="max_alerts"):
        SQLiteAlertRepository(tmp_path / "alerts.db", max_alerts=0)


def test_repository_creates_parent_and_round_trips_alert(tmp_path) -> None:
    path = tmp_path / "nested" / "alerts.db"
    alert = _alert()

    with SQLiteAlertRepository(path) as repository:
        repository.apply([alert])
        restored = repository.load()

    assert path.is_file()
    assert restored == [alert]


def test_repository_updates_one_stable_incident_identity(tmp_path) -> None:
    path = tmp_path / "alerts.db"
    first = _alert(event_count=5)
    updated = replace(first, id="updated-id", event_count=7, last_seen=NOW + timedelta(seconds=6))

    with SQLiteAlertRepository(path) as repository:
        repository.apply([first])
        repository.apply([updated])

        assert repository.count() == 1
        assert repository.load() == [updated]


def test_repository_capacity_keeps_newest_alerts(tmp_path) -> None:
    alerts = [
        _alert("203.0.113.1", seconds=0),
        _alert("203.0.113.2", seconds=10),
        _alert("203.0.113.3", seconds=20),
    ]

    with SQLiteAlertRepository(tmp_path / "alerts.db", max_alerts=2) as repository:
        repository.apply(alerts)
        restored = repository.load()

        assert repository.count() == 2

    assert [alert.actor for alert in restored] == ["203.0.113.3", "203.0.113.2"]


def test_repository_explicit_delete_removes_alert(tmp_path) -> None:
    alert = _alert()

    with SQLiteAlertRepository(tmp_path / "alerts.db") as repository:
        repository.apply([alert])
        repository.apply([], deleted=[alert_identity(alert)])

        assert repository.load() == []


def test_repository_discards_one_malformed_row(tmp_path) -> None:
    path = tmp_path / "alerts.db"
    valid = _alert()
    with SQLiteAlertRepository(path) as repository:
        repository.apply([valid])
        with sqlite3.connect(path) as connection:
            connection.execute(
                "INSERT INTO alerts(identity, last_seen, payload) VALUES (?, ?, ?)",
                ("bad-row", NOW.isoformat(), "not-json"),
            )

        assert repository.load() == [valid]
        assert repository.count() == 1


def test_repository_close_is_idempotent_and_rejects_use(tmp_path) -> None:
    repository = SQLiteAlertRepository(tmp_path / "alerts.db")

    repository.close()
    repository.close()

    with pytest.raises(RuntimeError, match="closed"):
        repository.load()


def test_server_health_reports_memory_by_default() -> None:
    app = create_app()

    assert _request(app, "GET", "/health").json()["persistence"] == "memory"


def test_server_health_reports_sqlite_when_configured(tmp_path) -> None:
    app = create_app(alert_db_path=tmp_path / "alerts.db")
    try:
        assert _request(app, "GET", "/health").json()["persistence"] == "sqlite"
    finally:
        app.state.store.repository.close()


def test_server_restores_alert_after_restart_without_raw_logs(tmp_path) -> None:
    path = tmp_path / "alerts.db"
    settings = DetectionConfig(
        brute_force_threshold=3,
        brute_force_window_seconds=60,
    )
    first = create_app(alert_db_path=path, config=settings)
    try:
        response = _request(
            first,
            "POST",
            "/ingest",
            json={"events": [_event(index) for index in range(3)]},
        )
        assert response.status_code == 202
        assert response.json()["alerts_created"] == 1
    finally:
        first.state.store.repository.close()

    assert "sensitive raw event" not in path.read_bytes().decode("utf-8", errors="ignore")

    second = create_app(alert_db_path=path, config=settings)
    try:
        restored = _request(second, "GET", "/alerts").json()
        assert restored["total"] == 1
        assert restored["alerts"][0]["type"] == "brute_force"
        assert restored["alerts"][0]["event_count"] == 3
    finally:
        second.state.store.repository.close()
