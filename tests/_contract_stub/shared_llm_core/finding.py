"""Test double for ``shared_llm_core.finding`` (v0.5 frozen schema).

Only the subset consumed by 001AI-SOC-Agent is reproduced. See
``tests/_contract_stub/README.md`` before touching anything here.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping, Sequence


class FindingSeverity(Enum):
    """Severity ladder shared by every product in the suite."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingSource(Enum):
    """Frozen product identifiers used for cross-product correlation."""

    SOC = "001"
    VULN = "002"
    THREAT_INTEL = "003"
    COMPLIANCE = "004"
    FORENSICS = "005"
    RESPONSE = "006"


def _as_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


@dataclass(frozen=True)
class Finding:
    """One normalized detection emitted by any suite product."""

    id: str
    source: FindingSource
    severity: FindingSeverity
    confidence: float
    title: str
    description: str
    host: str | None = None
    ts: datetime | None = None
    evidence: tuple[str, ...] = ()
    tags: frozenset[str] = field(default_factory=frozenset)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            object.__setattr__(self, "id", str(uuid.uuid4()))
        if not isinstance(self.evidence, tuple):
            object.__setattr__(self, "evidence", tuple(self.evidence))
        if not isinstance(self.tags, frozenset):
            object.__setattr__(self, "tags", frozenset(self.tags))

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable envelope shape."""
        return {
            "id": self.id,
            "source": self.source.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "host": self.host,
            "ts": self.ts.isoformat() if self.ts is not None else None,
            "evidence": list(self.evidence),
            "tags": sorted(self.tags),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Finding":
        """Rebuild a Finding from its ``to_dict`` envelope."""
        evidence: Sequence[str] = payload.get("evidence", ())
        return cls(
            id=str(payload.get("id", "")),
            source=FindingSource(payload["source"]),
            severity=FindingSeverity(payload["severity"]),
            confidence=float(payload.get("confidence", 0.0)),
            title=str(payload.get("title", "")),
            description=str(payload.get("description", "")),
            host=payload.get("host"),
            ts=_as_datetime(payload.get("ts")),
            evidence=tuple(str(item) for item in evidence),
            tags=frozenset(payload.get("tags", ())),
            metadata=dict(payload.get("metadata", {})),
        )
