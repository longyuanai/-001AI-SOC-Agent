"""Test double for ``shared_llm_core.finding`` (v0.5 frozen schema).

Only the subset consumed by 001AI-SOC-Agent is reproduced. See
``tests/_contract_stub/README.md`` before touching anything here.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


class FindingSeverity(str, Enum):
    """Severity ladder shared by every product in the suite."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingSource(str, Enum):
    """Frozen product identifiers used for cross-product correlation."""

    SOC = "001"
    VULN = "002"
    LAB = "003"
    CODE = "004"
    REVERSE = "005"
    FIRMWARE = "006"
    EXTERNAL = "external"


@dataclass(frozen=True)
class Finding:
    """One normalized detection emitted by any suite product."""

    id: str
    source: FindingSource
    severity: FindingSeverity
    confidence: float
    title: str
    description: str = ""
    host: str | None = None
    cve: str | None = None
    ts: datetime | None = None
    evidence: tuple[str, ...] = ()
    related: tuple[str, ...] = ()
    tags: frozenset[str] = frozenset()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in [0,1], got {self.confidence!r}")
        if not self.id:
            object.__setattr__(self, "id", str(uuid.uuid4()))

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-serializable envelope shape."""
        payload = asdict(self)
        payload["source"] = self.source.value
        payload["severity"] = self.severity.value
        if self.ts is not None:
            payload["ts"] = self.ts.isoformat()
        payload["evidence"] = list(self.evidence)
        payload["related"] = list(self.related)
        payload["tags"] = sorted(self.tags)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Finding":
        """Rebuild a Finding from its ``to_dict`` envelope."""
        known = {item.name for item in cls.__dataclass_fields__.values()}
        clean: dict[str, Any] = {
            key: value for key, value in payload.items() if key in known
        }
        if "source" in clean and isinstance(clean["source"], str):
            clean["source"] = FindingSource(clean["source"])
        if "severity" in clean and isinstance(clean["severity"], str):
            clean["severity"] = FindingSeverity(clean["severity"])
        if "ts" in clean and isinstance(clean["ts"], str):
            clean["ts"] = datetime.fromisoformat(clean["ts"])
        if "evidence" in clean and isinstance(clean["evidence"], list):
            clean["evidence"] = tuple(clean["evidence"])
        if "related" in clean and isinstance(clean["related"], list):
            clean["related"] = tuple(clean["related"])
        if "tags" in clean and isinstance(clean["tags"], list):
            clean["tags"] = frozenset(clean["tags"])
        return cls(**clean)
