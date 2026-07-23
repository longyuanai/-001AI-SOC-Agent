"""FastAPI webhook server for normalized security events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Annotated, Any, Literal

from fastapi import Body, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from ai_soc_agent.correlator import Alert, correlate
from ai_soc_agent.normalizer import NormalizedEvent


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


def create_app(*, max_events: int = 10_000) -> FastAPI:
    """Create an isolated API application with an in-memory event store."""
    if max_events <= 0:
        raise ValueError("max_events must be positive")

    app = FastAPI(title="AI-SOC-Agent", version="0.1.0")
    store = _Store(max_events=max_events)
    app.state.store = store

    @app.post("/ingest", status_code=202)
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

            correlated = correlate(store.events)
            created = [alert for alert in correlated if alert.id not in store.alerts]
            store.alerts.update((alert.id, alert) for alert in created)
            total_alerts = len(store.alerts)

        return {
            "accepted": len(normalized),
            "alerts_created": len(created),
            "alert_ids": [alert.id for alert in created],
            "total_alerts": total_alerts,
        }

    @app.get("/alerts")
    def get_alerts(
        alert_type: Annotated[str | None, Query(alias="type")] = None,
        limit: Annotated[int, Query(ge=1, le=1_000)] = 100,
    ) -> dict[str, Any]:
        with store.lock:
            alerts = list(store.alerts.values())
        if alert_type is not None:
            alerts = [alert for alert in alerts if alert.kind == alert_type]
        selected = alerts[:limit]
        return {
            "count": len(selected),
            "alerts": [alert.to_dict() for alert in selected],
        }

    return app


app = create_app()


def main() -> None:
    """Run the development ASGI server."""
    import uvicorn

    uvicorn.run("ai_soc_agent.server:app", host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
