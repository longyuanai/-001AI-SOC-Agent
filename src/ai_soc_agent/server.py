"""FastAPI webhook server for normalized security events."""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Annotated, Any, Literal

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ai_soc_agent import __version__
from ai_soc_agent.config import DetectionConfig
from ai_soc_agent.correlator import Alert, correlate
from ai_soc_agent.feedback import FeedbackLabel, FeedbackStore
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.state import WindowStateStore

logger = logging.getLogger(__name__)

# Widest rule window (geo anomaly, 24h). Events older than this relative to the
# newest event cannot contribute to a new alert, so they need not be re-scanned.
CORRELATION_HORIZON = timedelta(days=1)

# Upper bound on how many recent events one /ingest re-correlates. Without it,
# every request rescanned the entire store and cost grew with store size.
DEFAULT_MAX_CORRELATION_EVENTS = 5_000
DEFAULT_MAX_ALERTS = 5_000
DEFAULT_MAX_REQUEST_BYTES = 8 * 1024 * 1024


class EventIn(BaseModel):
    """Validated normalized-event payload accepted from ELK or Splunk."""

    ts: datetime
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    result: Literal["success", "failure", "unknown"]
    source: str = Field(min_length=1)
    raw: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    def to_event(self) -> NormalizedEvent:
        return NormalizedEvent(
            ts=self.ts,
            actor=self.actor,
            action=self.action,
            target=self.target,
            result=self.result,
            source=self.source,
            raw=self.raw,
            extra=self.extra,
        )


class EventBatch(BaseModel):
    """ELK-style batch envelope."""

    events: list[EventIn]


class SplunkEnvelope(BaseModel):
    """Splunk HEC-style single-event envelope."""

    event: EventIn


class FeedbackIn(BaseModel):
    """Validated human disposition for one Finding or Alert ID."""

    finding_id: str = Field(min_length=1)
    label: Literal["true_positive", "false_positive", "needs_review"]
    analyst: str = Field(min_length=1)
    note: str = Field(default="", max_length=4_000)


IngestPayload = EventBatch | SplunkEnvelope | list[EventIn] | EventIn


@dataclass
class _Store:
    event_state: WindowStateStore
    max_alerts: int
    max_correlation_events: int
    alerts: dict[tuple[str, str], Alert] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock)

    @property
    def max_events(self) -> int:
        return self.event_state.max_events


def _payload_events(payload: IngestPayload) -> list[EventIn]:
    if isinstance(payload, EventBatch):
        return payload.events
    if isinstance(payload, SplunkEnvelope):
        return [payload.event]
    if isinstance(payload, EventIn):
        return [payload]
    return payload


def _identity(alert: Alert) -> tuple[str, str]:
    """Stable key for one ongoing incident.

    ``Alert.id`` hashes first_seen/last_seen, so a sustained attack minted a new
    id on every ingest and the store filled with near-duplicates. Dedupe on the
    thing that actually identifies the incident instead.
    """
    return (alert.kind, alert.actor)


def _correlation_slice(store: _Store) -> list[NormalizedEvent]:
    """Return the recent events worth re-correlating."""
    return store.event_state.snapshot(limit=store.max_correlation_events)


def create_app(
    *,
    max_events: int = 10_000,
    max_alerts: int = DEFAULT_MAX_ALERTS,
    max_feedback: int = 5_000,
    max_correlation_events: int = DEFAULT_MAX_CORRELATION_EVENTS,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    api_token: str | None = None,
    config: DetectionConfig | None = None,
) -> FastAPI:
    """Create an isolated API application with an in-memory event store."""
    if max_events <= 0:
        raise ValueError("max_events must be positive")
    if max_alerts <= 0:
        raise ValueError("max_alerts must be positive")
    if max_feedback <= 0:
        raise ValueError("max_feedback must be positive")
    if max_correlation_events <= 0:
        raise ValueError("max_correlation_events must be positive")

    token = api_token if api_token is not None else os.environ.get("SOC_API_TOKEN")
    settings = config if config is not None else DetectionConfig.for_stream()

    app = FastAPI(title="AI-SOC-Agent", version=__version__)
    store = _Store(
        event_state=WindowStateStore(
            max_events=max_events,
            horizon=CORRELATION_HORIZON,
        ),
        max_alerts=max_alerts,
        max_correlation_events=max_correlation_events,
    )
    app.state.store = store
    app.state.config = settings
    feedback_store = FeedbackStore(max_records=max_feedback)
    app.state.feedback_store = feedback_store

    def require_token(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        """Reject unauthenticated writes when SOC_API_TOKEN is configured."""
        if not token:
            return
        supplied = ""
        if authorization and authorization.lower().startswith("bearer "):
            supplied = authorization[7:]
        if not hmac.compare_digest(supplied, token):
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

    @app.middleware("http")
    async def limit_body_size(request: Request, call_next):
        """Reject oversized bodies before they are buffered into memory."""
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > max_request_bytes:
            return _json_error(413, "request body exceeds limit")
        return await call_next(request)

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Liveness probe that does not serialize the alert store."""
        with store.lock:
            events = len(store.event_state)
            alerts = len(store.alerts)
        return {
            "status": "ok",
            "product": "001-soc",
            "version": __version__,
            "events": events,
            "alerts": alerts,
        }

    @app.post("/ingest", status_code=202, dependencies=[Depends(require_token)])
    def ingest(payload: Annotated[IngestPayload, Body()]) -> dict[str, Any]:
        incoming = _payload_events(payload)
        if not incoming:
            raise HTTPException(status_code=400, detail="at least one event is required")
        if len(incoming) > store.max_events:
            raise HTTPException(status_code=413, detail="event batch exceeds in-memory limit")

        normalized = [item.to_event() for item in incoming]

        # Snapshot under the lock, correlate outside it: correlation is the
        # expensive part and holding the lock across it serialized every request.
        with store.lock:
            state_result = store.event_state.append(normalized)
            candidates = _correlation_slice(store)

        correlated = correlate(candidates, config=settings)

        with store.lock:
            created: list[Alert] = []
            for alert in correlated:
                identity = _identity(alert)
                previous = store.alerts.get(identity)
                if previous is None:
                    created.append(alert)
                elif alert.event_count <= previous.event_count:
                    continue
                store.alerts[identity] = alert
            while len(store.alerts) > store.max_alerts:
                store.alerts.pop(next(iter(store.alerts)))
            total_alerts = len(store.alerts)

        logger.info(
            "ingested events=%d stored=%d duplicates=%d expired=%d "
            "correlated=%d new_alerts=%d total_alerts=%d",
            len(normalized),
            state_result.accepted,
            state_result.duplicates,
            state_result.expired,
            len(candidates),
            len(created),
            total_alerts,
        )
        return {
            "accepted": len(normalized),
            "alerts_created": len(created),
            "alert_ids": [alert.id for alert in created],
            "total_alerts": total_alerts,
        }

    @app.get("/alerts")
    def get_alerts(
        alert_type: Annotated[str | None, Query(alias="type")] = None,
        severity: Annotated[str | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        with store.lock:
            alerts = list(store.alerts.values())
        if alert_type is not None:
            alerts = [alert for alert in alerts if alert.kind == alert_type]
        if severity is not None:
            alerts = [alert for alert in alerts if alert.severity == severity]
        # Most recent first: insertion order buried an active incident under
        # whatever happened to be ingested earliest.
        alerts.sort(key=lambda alert: (alert.last_seen, alert.kind, alert.id), reverse=True)
        selected = alerts[offset : offset + limit]
        return {
            "count": len(selected),
            "total": len(alerts),
            "alerts": [alert.to_dict() for alert in selected],
        }

    @app.post(
        "/feedback",
        status_code=201,
        dependencies=[Depends(require_token)],
    )
    def add_feedback(payload: FeedbackIn) -> dict[str, str]:
        """Record an analyst label without changing a rule or threshold."""
        return feedback_store.add(
            finding_id=payload.finding_id,
            label=FeedbackLabel(payload.label),
            analyst=payload.analyst,
            note=payload.note,
        ).to_dict()

    @app.get("/feedback")
    def get_feedback(
        finding_id: Annotated[str | None, Query()] = None,
        label: Annotated[
            Literal["true_positive", "false_positive", "needs_review"] | None,
            Query(),
        ] = None,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> dict[str, Any]:
        normalized_label = FeedbackLabel(label) if label is not None else None
        records = feedback_store.query(
            finding_id=finding_id,
            label=normalized_label,
            limit=limit,
            offset=offset,
        )
        return {
            "count": len(records),
            "total": feedback_store.count(
                finding_id=finding_id,
                label=normalized_label,
            ),
            "summary": feedback_store.summary(),
            "feedback": [record.to_dict() for record in records],
        }

    return app


def _json_error(status_code: int, detail: str):
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=status_code, content={"detail": detail})


app = create_app()


def main() -> None:
    """Run the development ASGI server."""
    import uvicorn

    logging.basicConfig(
        level=os.environ.get("SOC_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    if not os.environ.get("SOC_API_TOKEN"):
        logger.warning(
            "SOC_API_TOKEN is unset: /ingest accepts unauthenticated writes. "
            "Set it before exposing this server beyond localhost."
        )
    uvicorn.run(
        "ai_soc_agent.server:app",
        host=os.environ.get("SOC_HOST", "127.0.0.1"),
        port=int(os.environ.get("SOC_PORT", "8080")),
    )


if __name__ == "__main__":
    main()
