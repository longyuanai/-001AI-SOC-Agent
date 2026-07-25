"""SOC Finding construction helpers for cross-product correlation."""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, ip_address
from typing import Any, Mapping

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource


def _value(event: Any, key: str, default: Any = None) -> Any:
    if isinstance(event, dict):
        if key in event:
            return event[key]
        extra = event.get("extra", {})
    else:
        if hasattr(event, key):
            return getattr(event, key)
        extra = getattr(event, "extra", {})
    return extra.get(key, default) if isinstance(extra, dict) else default


def correlation_host(event: Any) -> str | None:
    """Return the stable IP/host key shared-core correlation rules consume."""
    actor = _value(event, "actor", _value(event, "src_ip"))
    if actor not in (None, "", "-", "unknown"):
        try:
            parsed_actor = ip_address(str(actor))
        except ValueError:
            pass
        else:
            if isinstance(parsed_actor, IPv4Address):
                return str(parsed_actor)

    for key in ("host", "destination_host", "dest_host", "computer"):
        value = _value(event, key)
        if value not in (None, "", "-", "unknown"):
            return str(value)
    return None


def build_soc_finding(
    *,
    severity: FindingSeverity,
    confidence: float,
    title: str,
    description: str,
    host_event: Any,
    ts: datetime | None,
    evidence: tuple[str, ...],
    tags: frozenset[str],
    metadata: Mapping[str, Any],
    host: str | None = None,
) -> Finding:
    """Build a v0.5 Finding without modifying the frozen shared schema."""
    return Finding(
        id="",
        source=FindingSource.SOC,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        host=host if host is not None else correlation_host(host_event),
        ts=ts,
        evidence=evidence,
        tags=tags,
        metadata=metadata,
    )
