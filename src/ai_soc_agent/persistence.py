"""Optional bounded SQLite persistence for normalized SOC alerts."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from ai_soc_agent.correlator import Alert
from ai_soc_agent.normalizer import ensure_utc

logger = logging.getLogger(__name__)


def alert_identity(alert: Alert) -> str:
    """Return the stable ongoing-incident identity used by the API store."""
    return f"{alert.kind}\x1f{alert.actor}"


def _required_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"persisted alert {key!r} must be a non-empty string")
    return value


def _alert_from_dict(payload: dict[str, Any]) -> Alert:
    targets = payload.get("targets", [])
    sources = payload.get("sources", [])
    event_count = payload.get("event_count")
    if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
        raise ValueError("persisted alert targets must be a string list")
    if not isinstance(sources, list) or not all(isinstance(item, str) for item in sources):
        raise ValueError("persisted alert sources must be a string list")
    if not isinstance(event_count, int) or isinstance(event_count, bool) or event_count <= 0:
        raise ValueError("persisted alert event_count must be a positive integer")
    try:
        first_seen = ensure_utc(
            datetime.fromisoformat(
                _required_text(payload, "first_seen").replace("Z", "+00:00")
            )
        )
        last_seen = ensure_utc(
            datetime.fromisoformat(
                _required_text(payload, "last_seen").replace("Z", "+00:00")
            )
        )
    except ValueError as exc:
        raise ValueError("persisted alert timestamps must be ISO-8601") from exc
    if last_seen < first_seen:
        raise ValueError("persisted alert last_seen precedes first_seen")
    return Alert(
        id=_required_text(payload, "id"),
        kind=_required_text(payload, "type"),
        severity=_required_text(payload, "severity"),
        actor=_required_text(payload, "actor"),
        targets=tuple(targets),
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=event_count,
        sources=tuple(sources),
        summary=_required_text(payload, "summary"),
    )


class SQLiteAlertRepository:
    """Persist only normalized Alerts in one transactional, bounded table."""

    def __init__(self, path: str | Path, *, max_alerts: int = 5_000) -> None:
        if max_alerts <= 0:
            raise ValueError("max_alerts must be positive")
        self.path = Path(path)
        self.max_alerts = max_alerts
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            str(path),
            timeout=5.0,
            check_same_thread=False,
        )
        self._closed = False
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    identity TEXT PRIMARY KEY,
                    last_seen TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            self._prune_locked()

    def load(self) -> list[Alert]:
        """Load newest valid alerts, isolating malformed individual rows."""
        self._ensure_open()
        rows = self._connection.execute(
            "SELECT identity, payload FROM alerts ORDER BY last_seen DESC LIMIT ?",
            (self.max_alerts,),
        ).fetchall()
        alerts: list[Alert] = []
        invalid: list[str] = []
        for identity, encoded in rows:
            try:
                payload = json.loads(encoded)
                if not isinstance(payload, dict):
                    raise ValueError("payload is not an object")
                alert = _alert_from_dict(payload)
                if alert_identity(alert) != identity:
                    raise ValueError("identity does not match payload")
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                logger.warning("discarding invalid persisted alert %r: %s", identity, exc)
                invalid.append(identity)
                continue
            alerts.append(alert)
        if invalid:
            with self._connection:
                self._connection.executemany(
                    "DELETE FROM alerts WHERE identity = ?",
                    ((identity,) for identity in invalid),
                )
        return alerts

    def apply(
        self,
        alerts: Iterable[Alert],
        *,
        deleted: Iterable[str] = (),
    ) -> None:
        """Atomically upsert changed alerts, delete evictions, and enforce capacity."""
        self._ensure_open()
        changed = list(alerts)
        removed = tuple(deleted)
        with self._connection:
            if changed:
                self._connection.executemany(
                    """
                    INSERT INTO alerts(identity, last_seen, payload) VALUES (?, ?, ?)
                    ON CONFLICT(identity) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        payload = excluded.payload
                    """,
                    (
                        (
                            alert_identity(alert),
                            ensure_utc(alert.last_seen).isoformat(),
                            json.dumps(
                                alert.to_dict(),
                                ensure_ascii=False,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        )
                        for alert in changed
                    ),
                )
            if removed:
                self._connection.executemany(
                    "DELETE FROM alerts WHERE identity = ?",
                    ((identity,) for identity in removed),
                )
            self._prune_locked()

    def count(self) -> int:
        self._ensure_open()
        row = self._connection.execute("SELECT COUNT(*) FROM alerts").fetchone()
        return int(row[0])

    def close(self) -> None:
        if self._closed:
            return
        self._connection.close()
        self._closed = True

    def _prune_locked(self) -> None:
        self._connection.execute(
            """
            DELETE FROM alerts
            WHERE identity IN (
                SELECT identity FROM alerts
                ORDER BY last_seen DESC, identity DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (self.max_alerts,),
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("alert repository is closed")

    def __enter__(self) -> "SQLiteAlertRepository":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


__all__ = ["SQLiteAlertRepository", "alert_identity"]
