"""Normalized representation of one log line.

The point of normalizing here is so the analyzer (and the LLM) can work on a
stable shape regardless of which log format the input file uses. New parsers
plug in by emitting `NormalizedEvent`; the rest of the pipeline doesn't care.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime.

    Log sources disagree about timezones: syslog (sshd) carries none, while
    Windows Event XML, Nginx, and Okta all carry offsets. Mixing the two kinds
    in one list makes ``min()``/``max()``/``sorted()`` raise ``TypeError``, so
    every event is pinned to UTC at construction.

    Naive input is *assumed* to already be UTC. That is the assumption the
    correlation code has always made; feed sshd logs from a non-UTC host
    through a shipper that stamps offsets if you need true local time.
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True)
class NormalizedEvent:
    """One security-relevant event, post-normalization.

    ``ts`` is always timezone-aware UTC — see :func:`ensure_utc`.
    """

    ts: datetime
    actor: str  # who initiated (src IP, user, process)
    action: str  # what they tried (login, exec, file_read, ...)
    target: str  # what they targeted (host, user, file)
    result: str  # "success" | "failure" | "unknown"
    source: str  # which parser produced this ("sshd", "auth", ...)
    raw: str = ""  # original line, for traceability
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "ts", ensure_utc(self.ts))

    def to_prompt_dict(self) -> dict[str, Any]:
        """Compact JSON-serializable form, used in the LLM prompt."""
        return {
            "ts": self.ts.isoformat(),
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "result": self.result,
            "source": self.source,
            "extra": self.extra,
        }