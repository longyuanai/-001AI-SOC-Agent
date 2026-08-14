"""Bounded Elasticsearch ingestion using the existing event parsers."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from shared_llm_core.untrusted import wrap_untrusted

from ai_soc_agent.normalizer import NormalizedEvent, ensure_utc
from ai_soc_agent.parsers import (
    parse_evtx_line,
    parse_line,
    parse_nginx_line,
    parse_okta_record,
)

ELASTIC_URL_ENV = "AI_SOC_ELASTIC_URL"
ELASTIC_INDEX_ENV = "AI_SOC_ELASTIC_INDEX"
ELASTIC_API_KEY_ENV = "AI_SOC_ELASTIC_API_KEY"
DEFAULT_PAGE_SIZE = 500
DEFAULT_MAX_PAGES = 100
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_NORMALIZED_FIELDS = {"actor", "action", "target", "result"}


class ElasticSourceError(RuntimeError):
    """Elasticsearch could not return a trustworthy, bounded response."""


class ElasticConfigurationError(ElasticSourceError):
    """Required Elasticsearch connection settings are absent or invalid."""


@dataclass(frozen=True, slots=True)
class ElasticSettings:
    """Connection settings loaded from environment variables."""

    url: str
    index: str
    api_key: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> ElasticSettings:
        values = os.environ if environ is None else environ
        missing = [
            name
            for name in (ELASTIC_URL_ENV, ELASTIC_INDEX_ENV, ELASTIC_API_KEY_ENV)
            if not values.get(name, "").strip()
        ]
        if missing:
            raise ElasticConfigurationError(
                "missing Elasticsearch configuration: " + ", ".join(missing)
            )

        url = values[ELASTIC_URL_ENV].strip().rstrip("/")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ElasticConfigurationError(
                f"{ELASTIC_URL_ENV} must be an absolute http(s) URL"
            )
        if parsed.username is not None or parsed.password is not None:
            raise ElasticConfigurationError(
                f"{ELASTIC_URL_ENV} must not embed credentials"
            )

        index = values[ELASTIC_INDEX_ENV].strip()
        if "/" in index or "\\" in index:
            raise ElasticConfigurationError(
                f"{ELASTIC_INDEX_ENV} must be an index name or pattern, not a path"
            )
        return cls(
            url=url,
            index=index,
            api_key=values[ELASTIC_API_KEY_ENV].strip(),
        )


@dataclass(frozen=True, slots=True)
class ElasticRequest:
    """One injectable HTTP request, kept small for offline tests."""

    url: str
    body: bytes
    headers: Mapping[str, str]
    timeout_seconds: float


ElasticTransport = Callable[[ElasticRequest], Mapping[str, Any]]


def fetch_events(
    *,
    query: str | Mapping[str, Any],
    start: datetime,
    end: datetime,
    log_type: str = "sshd",
    page_size: int = DEFAULT_PAGE_SIZE,
    max_pages: int = DEFAULT_MAX_PAGES,
    settings: ElasticSettings | None = None,
    transport: ElasticTransport | None = None,
) -> list[NormalizedEvent]:
    """Fetch and normalize events from one Elasticsearch time window.

    Pagination is bounded by ``max_pages``. A full final page raises instead
    of silently returning an incomplete result set.
    """

    if page_size <= 0:
        raise ValueError("page_size must be positive")
    if max_pages <= 0:
        raise ValueError("max_pages must be positive")
    start_utc = ensure_utc(start)
    end_utc = ensure_utc(end)
    if start_utc >= end_utc:
        raise ValueError("start must be earlier than end")

    active_settings = settings or ElasticSettings.from_env()
    active_transport = transport or _urlopen_transport
    endpoint = (
        f"{active_settings.url}/"
        f"{quote(active_settings.index, safe='*,-_.')}/_search"
    )
    headers = {
        "Accept": "application/json",
        "Authorization": f"ApiKey {active_settings.api_key}",
        "Content-Type": "application/json",
    }
    query_clause = _query_clause(query)
    events: list[NormalizedEvent] = []
    offset = 0

    for _page in range(max_pages):
        body = {
            "from": offset,
            "size": page_size,
            "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": _isoformat(start_utc),
                                    "lte": _isoformat(end_utc),
                                }
                            }
                        }
                    ],
                    "must": [query_clause],
                }
            },
        }
        request = ElasticRequest(
            url=endpoint,
            body=json.dumps(body, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            timeout_seconds=active_settings.timeout_seconds,
        )
        response = active_transport(request)
        hits = _response_hits(response)
        for hit in hits:
            event = _event_from_hit(hit, log_type=log_type)
            if event is not None:
                events.append(event)
        if len(hits) < page_size:
            return events
        offset += len(hits)

    raise ElasticSourceError(
        f"Elasticsearch pagination exceeded the configured max_pages={max_pages}"
    )


def _query_clause(query: str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(query, str):
        text = query.strip()
        if not text or text == "*":
            return {"match_all": {}}
        return {"query_string": {"query": text}}
    if not isinstance(query, Mapping) or not query:
        raise ValueError("query must be a non-empty string or Elasticsearch query object")
    return dict(query)


def _response_hits(response: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    if not isinstance(response, Mapping):
        raise ElasticSourceError("Elasticsearch response must be a JSON object")
    hits_container = response.get("hits")
    if not isinstance(hits_container, Mapping):
        raise ElasticSourceError("Elasticsearch response is missing hits")
    hits = hits_container.get("hits")
    if not isinstance(hits, list) or not all(isinstance(hit, Mapping) for hit in hits):
        raise ElasticSourceError("Elasticsearch response hits must be a list of objects")
    return hits


def _event_from_hit(
    hit: Mapping[str, Any],
    *,
    log_type: str,
) -> NormalizedEvent | None:
    source = hit.get("_source")
    if not isinstance(source, Mapping):
        return None
    raw = _raw_content(source)
    event = _normalized_source_event(source, raw=raw, log_type=log_type)
    if event is None and log_type == "okta":
        event = parse_okta_record(dict(source))
    if event is None:
        event = _parse_raw(raw, log_type=log_type)
    if event is None:
        return None

    provenance = dict(event.extra)
    if hit.get("_index") is not None:
        provenance["elastic_index"] = str(hit["_index"])
    if hit.get("_id") is not None:
        provenance["elastic_id"] = str(hit["_id"])
    return replace(
        event,
        raw=wrap_untrusted(event.raw or raw, kind="log_event"),
        extra=provenance,
    )


def _normalized_source_event(
    source: Mapping[str, Any],
    *,
    raw: str,
    log_type: str,
) -> NormalizedEvent | None:
    timestamp = source.get("ts", source.get("@timestamp"))
    if not isinstance(timestamp, str) or not _NORMALIZED_FIELDS.issubset(source):
        return None
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    extra = source.get("extra", {})
    if not isinstance(extra, Mapping):
        extra = {}
    return NormalizedEvent(
        ts=parsed_timestamp,
        actor=str(source["actor"]),
        action=str(source["action"]),
        target=str(source["target"]),
        result=str(source["result"]),
        source=str(source.get("source", log_type)),
        raw=raw,
        extra=dict(extra),
    )


def _raw_content(source: Mapping[str, Any]) -> str:
    for key in ("message", "event.original", "log.original"):
        value = source.get(key)
        if isinstance(value, str) and value:
            return value
    return json.dumps(source, ensure_ascii=False, separators=(",", ":"), default=str)


def _parse_raw(raw: str, *, log_type: str) -> NormalizedEvent | None:
    if log_type == "sshd":
        return parse_line(raw)
    if log_type == "evtx":
        return parse_evtx_line(raw)
    if log_type == "nginx":
        return parse_nginx_line(raw)
    if log_type == "okta":
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parse_okta_record(record) if isinstance(record, dict) else None
    raise ValueError(f"unsupported log_type: {log_type}")


def _isoformat(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _urlopen_transport(request: ElasticRequest) -> Mapping[str, Any]:
    http_request = Request(
        request.url,
        data=request.body,
        headers=dict(request.headers),
        method="POST",
    )
    try:
        with urlopen(http_request, timeout=request.timeout_seconds) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        raise ElasticSourceError(
            f"Elasticsearch request failed with HTTP {error.code}"
        ) from error
    except (TimeoutError, URLError, OSError) as error:
        raise ElasticSourceError(
            f"Elasticsearch request failed: {type(error).__name__}"
        ) from error
    if len(payload) > MAX_RESPONSE_BYTES:
        raise ElasticSourceError("Elasticsearch response exceeded 8 MiB")
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ElasticSourceError("Elasticsearch response was not valid JSON") from error
    if not isinstance(decoded, Mapping):
        raise ElasticSourceError("Elasticsearch response must be a JSON object")
    return decoded


__all__ = [
    "ElasticConfigurationError",
    "ElasticRequest",
    "ElasticSettings",
    "ElasticSourceError",
    "fetch_events",
]
