"""FastAPI webhook server for normalized security events."""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from threading import Lock
from typing import Annotated, Any, Literal

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field

from ai_soc_agent import __version__
from ai_soc_agent.config import MAX_RULE_WINDOW_SECONDS
from ai_soc_agent.correlator import Alert, correlate
from ai_soc_agent.normalizer import NormalizedEvent

logger = logging.getLogger(__name__)

#: Env var holding the bearer token required by /ingest and /alerts. Unset means
#: the API is open, which is only appropriate on a trusted loopback interface.
API_TOKEN_ENV = "AI_SOC_API_TOKEN"


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


IngestPayload = EventBatch | SplunkEnvelope | list[EventIn] | EventIn


@dataclass
class _Store:
    max_events: int
    events: list[NormalizedEvent] = field(default_factory=list)
    alerts: dict[str, Alert] = field(default_factory=dict)
    lock: Lock = field(default_factory=Lock)


def _payload_events(payload: IngestPayload) -> list[EventIn]:
    if isinstance(payload, EventBatch):
        return payload.events
    if isinstance(payload, SplunkEnvelope):
        return [payload.event]
    if isinstance(payload, EventIn):
        return [payload]
    return payload


def _utc(value: datetime) -> datetime:
    """Treat naive timestamps as UTC; ELK and Splunk disagree on sending them."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _correlation_slice(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Return only the history a rule can still match on.

    ``/ingest`` used to re-correlate the entire 10k-event store on every request,
    so cost grew with uptime. No rule looks back further than
    ``MAX_RULE_WINDOW_SECONDS``, so older events cannot change the outcome.
    """
    if not events:
        return []
    cutoff = max(_utc(event.ts) for event in events).timestamp() - MAX_RULE_WINDOW_SECONDS
    return [event for event in events if _utc(event.ts).timestamp() >= cutoff]


def _merge(existing: Alert, incoming: Alert) -> Alert:
    """Widen a stored alert with a later observation of the same incident."""
    return replace(
        incoming,
        first_seen=min(existing.first_seen, incoming.first_seen, key=_utc),
        last_seen=max(existing.last_seen, incoming.last_seen, key=_utc),
        event_count=max(existing.event_count, incoming.event_count),
        targets=tuple(sorted(set(existing.targets) | set(incoming.targets))),
        sources=tuple(sorted(set(existing.sources) | set(incoming.sources))),
    )


def _token_guard(expected: str | None):
    """Build the bearer-token dependency for one app instance."""

    def guard(authorization: Annotated[str | None, Header()] = None) -> None:
        if expected is None:
            return
        scheme, _, presented = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(presented, expected):
            raise HTTPException(
                status_code=401,
                detail="missing or invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return guard


def create_app(*, max_events: int = 10_000, api_token: str | None = None) -> FastAPI:
    """Create an isolated API application with an in-memory event store."""
    if max_events <= 0:
        raise ValueError("max_events must be positive")

    expected_token = api_token or os.environ.get(API_TOKEN_ENV) or None
    if expected_token is None:
        logger.warning(
            "%s is not set: /ingest and /alerts accept unauthenticated requests. "
            "Keep the port on loopback or set a token before exposing it.",
            API_TOKEN_ENV,
        )

    app = FastAPI(title="AI-SOC-Agent", version=__version__)
    store = _Store(max_events=max_events)
    app.state.store = store
    require_token = Depends(_token_guard(expected_token))

    @app.post("/ingest", status_code=202, dependencies=[require_token])
    def ingest(payload: Annotated[IngestPayload, Body()]) -> dict[str, Any]:
        incoming = _payload_events(payload)
        if not incoming:
            raise HTTPException(status_code=400, detail="at least one event is required")
        if len(incoming) > store.max_events:
            raise HTTPException(status_code=413, detail="event batch exceeds in-memory limit")

        normalized = [item.to_event() for item in incoming]
        with store.lock:
            store.events.extend(normalized)
            if len(store.events) > store.max_events:
                del store.events[: len(store.events) - store.max_events]
            recent = _correlation_slice(store.events)

        # Correlation deliberately runs outside the lock: it is the expensive
        # part, and holding the lock across it serialized concurrent ingests.
        correlated = correlate(recent)

        with store.lock:
            created = [alert for alert in correlated if alert.id not in store.alerts]
            for alert in correlated:
                stored = store.alerts.get(alert.id)
                store.alerts[alert.id] = alert if stored is None else _merge(stored, alert)
            total_alerts = len(store.alerts)

        return {
            "accepted": len(normalized),
            "alerts_created": len(created),
            "alert_ids": [alert.id for alert in created],
            "total_alerts": total_alerts,
        }

    @app.get("/alerts", dependencies=[require_token])
    def get_alerts(
        alert_type: Annotated[str | None, Query(alias="type")] = None,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
    ) -> dict[str, Any]:
        with store.lock:
            alerts = list(store.alerts.values())
        if alert_type is not None:
            alerts = [alert for alert in alerts if alert.kind == alert_type]
        alerts.sort(key=lambda alert: (_utc(alert.first_seen), alert.kind, alert.id))
        selected = alerts[:limit]
        return {
            "count": len(selected),
            "alerts": [alert.to_dict() for alert in selected],
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        """Unauthenticated liveness probe; reports counters only, never events."""
        with store.lock:
            event_count = len(store.events)
            alert_count = len(store.alerts)
        return {
            "status": "ok",
            "version": __version__,
            "events": event_count,
            "alerts": alert_count,
            "auth_required": expected_token is not None,
        }

    return app


app = create_app()


def main() -> None:
    """Run the development ASGI server; loopback unless told otherwise."""
    import uvicorn

    uvicorn.run(
        "ai_soc_agent.server:app",
        host=os.environ.get("AI_SOC_HOST", "127.0.0.1"),
        port=int(os.environ.get("AI_SOC_PORT", "8080")),
    )


if __name__ == "__main__":
    main()
