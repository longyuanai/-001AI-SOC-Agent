from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ai_soc_agent.sources.elastic import (
    ELASTIC_API_KEY_ENV,
    ELASTIC_INDEX_ENV,
    ELASTIC_URL_ENV,
    ElasticConfigurationError,
    ElasticRequest,
    ElasticSettings,
    ElasticSourceError,
    fetch_events,
)

START = datetime(2026, 8, 14, 1, 0, tzinfo=UTC)
END = datetime(2026, 8, 14, 2, 0, tzinfo=UTC)
SETTINGS = ElasticSettings(
    url="https://elastic.example.invalid",
    index="synthetic-security-*",
    api_key="synthetic-api-key",
)
SSHD_LINE = (
    "Aug 14 01:30:00 synthetic-host sshd[1234]: Failed password for root "
    "from 203.0.113.8 port 51234 ssh2"
)


def _response(*hits: dict) -> dict:
    return {"hits": {"hits": list(hits)}}


def _hit(source: dict, *, hit_id: str = "synthetic-1") -> dict:
    return {
        "_index": "synthetic-security-2026.08.14",
        "_id": hit_id,
        "_source": source,
    }


def test_query_maps_hits_to_normalized_events() -> None:
    requests: list[ElasticRequest] = []

    def transport(request: ElasticRequest) -> dict:
        requests.append(request)
        return _response(_hit({"@timestamp": START.isoformat(), "message": SSHD_LINE}))

    events = fetch_events(
        query="event.category:authentication",
        start=START,
        end=END,
        settings=SETTINGS,
        transport=transport,
    )

    assert len(events) == 1
    assert events[0].actor == "203.0.113.8"
    assert events[0].target == "root"
    assert events[0].extra["elastic_id"] == "synthetic-1"
    assert '<UNTRUSTED_DATA kind="log_event">' in events[0].raw
    assert requests[0].headers["Authorization"].startswith("ApiKey ")


def test_missing_credentials_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (ELASTIC_URL_ENV, ELASTIC_INDEX_ENV, ELASTIC_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(ElasticConfigurationError, match=ELASTIC_API_KEY_ENV):
        ElasticSettings.from_env()


def test_time_window_is_applied() -> None:
    bodies = []

    def transport(request: ElasticRequest) -> dict:
        bodies.append(json.loads(request.body))
        return _response()

    fetch_events(
        query={"term": {"event.category": "authentication"}},
        start=START,
        end=END,
        settings=SETTINGS,
        transport=transport,
    )

    window = bodies[0]["query"]["bool"]["filter"][0]["range"]["@timestamp"]
    assert window == {"gte": "2026-08-14T01:00:00Z", "lte": "2026-08-14T02:00:00Z"}


def test_pagination_terminates() -> None:
    offsets = []
    responses = [
        _response(
            _hit({"message": SSHD_LINE}, hit_id="synthetic-1"),
            _hit({"message": SSHD_LINE}, hit_id="synthetic-2"),
        ),
        _response(),
    ]

    def transport(request: ElasticRequest) -> dict:
        offsets.append(json.loads(request.body)["from"])
        return responses.pop(0)

    events = fetch_events(
        query="*",
        start=START,
        end=END,
        page_size=2,
        settings=SETTINGS,
        transport=transport,
    )

    assert offsets == [0, 2]
    assert len(events) == 2


def test_full_final_page_fails_instead_of_silently_truncating() -> None:
    with pytest.raises(ElasticSourceError, match="max_pages=1"):
        fetch_events(
            query="*",
            start=START,
            end=END,
            page_size=1,
            max_pages=1,
            settings=SETTINGS,
            transport=lambda _request: _response(_hit({"message": SSHD_LINE})),
        )
