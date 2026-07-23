"""Normalized representation of one log line.

The point of normalizing here is so the analyzer (and the LLM) can work on a
stable shape regardless of which log format the input file uses. New parsers
plug in by emitting `NormalizedEvent`; the rest of the pipeline doesn't care.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class NormalizedEvent:
    """One security-relevant event, post-normalization."""

    ts: datetime
    actor: str  # who initiated (src IP, user, process)
    action: str  # what they tried (login, exec, file_read, ...)
    target: str  # what they targeted (host, user, file)
    result: str  # "success" | "failure" | "unknown"
    source: str  # which parser produced this ("sshd", "auth", ...)
    raw: str = ""  # original line, for traceability
    extra: dict[str, Any] = field(default_factory=dict)

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