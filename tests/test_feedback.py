"""Human-only feedback storage and API tests for FEEDBACK-001."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from ai_soc_agent.config import DetectionConfig
from ai_soc_agent.feedback import FeedbackLabel, FeedbackStore
from ai_soc_agent.server import create_app

NOW = datetime(2026, 7, 29, 14, 0, tzinfo=UTC)


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())


def test_feedback_labels_are_frozen_to_three_values() -> None:
    assert {label.value for label in FeedbackLabel} == {
        "true_positive",
        "false_positive",
        "needs_review",
    }


def test_feedback_store_adds_auditable_record() -> None:
    store = FeedbackStore(clock=lambda: NOW)

    record = store.add(
        finding_id="finding-1",
        label=FeedbackLabel.TRUE_POSITIVE,
        analyst="alice",
        note="confirmed from host telemetry",
    )

    assert uuid.UUID(record.id).version == 4
    assert record.ts == NOW
    assert record.to_dict()["label"] == "true_positive"


def test_feedback_store_evicts_oldest_at_capacity() -> None:
    current = [NOW]
    store = FeedbackStore(max_records=2, clock=lambda: current[0])
    store.add("finding-1", FeedbackLabel.TRUE_POSITIVE, "alice")
    current[0] += timedelta(seconds=1)
    store.add("finding-2", FeedbackLabel.FALSE_POSITIVE, "alice")
    current[0] += timedelta(seconds=1)
    store.add("finding-3", FeedbackLabel.NEEDS_REVIEW, "bob")

    assert [record.finding_id for record in store.query()] == [
        "finding-3",
        "finding-2",
    ]


def test_feedback_query_filters_finding_and_label() -> None:
    store = FeedbackStore(clock=lambda: NOW)
    store.add("finding-1", FeedbackLabel.TRUE_POSITIVE, "alice")
    store.add("finding-1", FeedbackLabel.NEEDS_REVIEW, "bob")
    store.add("finding-2", FeedbackLabel.TRUE_POSITIVE, "carol")

    assert len(store.query(finding_id="finding-1")) == 2
    assert len(store.query(label=FeedbackLabel.TRUE_POSITIVE)) == 2
    assert len(
        store.query(
            finding_id="finding-1",
            label=FeedbackLabel.NEEDS_REVIEW,
        )
    ) == 1


def test_feedback_query_is_newest_first_with_pagination() -> None:
    current = [NOW]
    store = FeedbackStore(clock=lambda: current[0])
    for index in range(4):
        store.add(f"finding-{index}", FeedbackLabel.NEEDS_REVIEW, "alice")
        current[0] += timedelta(seconds=1)

    page = store.query(limit=2, offset=1)

    assert [record.finding_id for record in page] == ["finding-2", "finding-1"]


def test_feedback_summary_counts_labels() -> None:
    store = FeedbackStore(clock=lambda: NOW)
    store.add("finding-1", FeedbackLabel.TRUE_POSITIVE, "alice")
    store.add("finding-2", FeedbackLabel.TRUE_POSITIVE, "bob")
    store.add("finding-3", FeedbackLabel.FALSE_POSITIVE, "carol")

    assert store.summary() == {
        "true_positive": 2,
        "false_positive": 1,
        "needs_review": 0,
    }


def test_feedback_api_creates_and_lists_record() -> None:
    app = create_app()
    payload = {
        "finding_id": "finding-1",
        "label": "true_positive",
        "analyst": "alice",
        "note": "validated",
    }

    created = _request(app, "POST", "/feedback", json=payload)
    listed = _request(app, "GET", "/feedback")

    assert created.status_code == 201
    assert created.json()["finding_id"] == "finding-1"
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["summary"]["true_positive"] == 1


def test_feedback_api_rejects_unknown_label() -> None:
    app = create_app()

    response = _request(
        app,
        "POST",
        "/feedback",
        json={
            "finding_id": "finding-1",
            "label": "maybe",
            "analyst": "alice",
        },
    )

    assert response.status_code == 422


def test_feedback_write_uses_same_bearer_auth() -> None:
    app = create_app(api_token="secret")
    payload = {
        "finding_id": "finding-1",
        "label": "needs_review",
        "analyst": "alice",
    }

    denied = _request(app, "POST", "/feedback", json=payload)
    allowed = _request(
        app,
        "POST",
        "/feedback",
        json=payload,
        headers={"Authorization": "Bearer secret"},
    )

    assert denied.status_code == 401
    assert allowed.status_code == 201


def test_feedback_state_is_isolated_per_app() -> None:
    first = create_app()
    second = create_app()
    payload = {
        "finding_id": "finding-1",
        "label": "false_positive",
        "analyst": "alice",
    }
    _request(first, "POST", "/feedback", json=payload)

    assert _request(first, "GET", "/feedback").json()["total"] == 1
    assert _request(second, "GET", "/feedback").json()["total"] == 0


def test_feedback_never_mutates_detection_config() -> None:
    config = DetectionConfig(brute_force_threshold=7)
    app = create_app(config=config)
    payload = {
        "finding_id": "finding-1",
        "label": "false_positive",
        "analyst": "alice",
    }

    _request(app, "POST", "/feedback", json=payload)

    assert app.state.config is config
    assert app.state.config.brute_force_threshold == 7


def test_feedback_store_and_app_reject_invalid_capacity() -> None:
    with pytest.raises(ValueError, match="max_records"):
        FeedbackStore(max_records=0)
    with pytest.raises(ValueError, match="max_feedback"):
        create_app(max_feedback=0)
