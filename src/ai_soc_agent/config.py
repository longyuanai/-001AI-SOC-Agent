"""Detection tuning: one source of truth for thresholds and suppression.

Thresholds used to be duplicated across ``cli.py`` (5), ``correlator.py`` (10),
and each rule module (5), so the same log produced different findings depending
on whether it arrived via the CLI, the gateway, or the API. Everything now
reads from here, and every value can be overridden per deployment through the
environment without editing code.
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_BRUTE_FORCE_THRESHOLD = 5
DEFAULT_BRUTE_FORCE_WINDOW_SECONDS = 60.0
DEFAULT_PRIV_ESC_THRESHOLD = 3
DEFAULT_PRIV_ESC_WINDOW_SECONDS = 120.0
DEFAULT_LATERAL_HOST_THRESHOLD = 3
DEFAULT_LATERAL_WINDOW_SECONDS = 600.0
DEFAULT_GEO_CONTINENT_THRESHOLD = 2
DEFAULT_GEO_WINDOW_SECONDS = 86_400.0
DEFAULT_CREDENTIAL_USER_THRESHOLD = 3
DEFAULT_CREDENTIAL_WINDOW_SECONDS = 300.0
DEFAULT_CROSS_SOURCE_WINDOW_SECONDS = 600.0
DEFAULT_REQUIRED_FAMILIES = frozenset({"ssh", "vpn", "web"})

# Hard cap on events retained per sliding window. Bounds both the evidence a
# single finding can carry and the per-event cost of re-qualifying a window.
MAX_WINDOW_EVENTS = 512

_ENV_PREFIX = "SOC_"


def _env_number(name: str, default: float) -> float:
    raw = os.environ.get(f"{_ENV_PREFIX}{name}")
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("ignoring non-numeric %s%s=%r", _ENV_PREFIX, name, raw)
        return default
    if value <= 0:
        logger.warning("ignoring non-positive %s%s=%r", _ENV_PREFIX, name, raw)
        return default
    return value


def _env_set(name: str) -> frozenset[str]:
    raw = os.environ.get(f"{_ENV_PREFIX}{name}", "")
    return frozenset(item.strip() for item in raw.split(",") if item.strip())


@dataclass(frozen=True)
class Suppression:
    """Actors whose activity should never raise a finding.

    Vulnerability scanners, monitoring probes, and jump hosts generate exactly
    the traffic these rules look for. Without a way to exclude them the product
    produces the alert fatigue it is meant to remove.
    """

    actors: frozenset[str] = field(default_factory=frozenset)
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @classmethod
    def from_env(cls) -> "Suppression":
        """Build from ``SOC_SUPPRESS_ACTORS`` / ``SOC_SUPPRESS_NETWORKS``."""
        networks = []
        for item in _env_set("SUPPRESS_NETWORKS"):
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                logger.warning("ignoring malformed %sSUPPRESS_NETWORKS entry %r", _ENV_PREFIX, item)
        return cls(
            actors=frozenset(item.casefold() for item in _env_set("SUPPRESS_ACTORS")),
            networks=tuple(networks),
        )

    def __bool__(self) -> bool:
        return bool(self.actors or self.networks)

    def suppresses(self, actor: Any) -> bool:
        """Return whether ``actor`` is on the allowlist."""
        if actor is None:
            return False
        text = str(actor)
        if text.casefold() in self.actors:
            return True
        if not self.networks:
            return False
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        return any(address in network for network in self.networks)


@dataclass(frozen=True)
class DetectionConfig:
    """Effective detection tuning for one process."""

    brute_force_threshold: int = DEFAULT_BRUTE_FORCE_THRESHOLD
    brute_force_window_seconds: float = DEFAULT_BRUTE_FORCE_WINDOW_SECONDS
    credential_stuffing_window_seconds: float = DEFAULT_CROSS_SOURCE_WINDOW_SECONDS
    suppression: Suppression = field(default_factory=Suppression)

    @classmethod
    def from_env(cls) -> "DetectionConfig":
        """Build from ``SOC_*`` environment variables, falling back to defaults."""
        return cls(
            brute_force_threshold=int(
                _env_number("BRUTE_FORCE_THRESHOLD", DEFAULT_BRUTE_FORCE_THRESHOLD)
            ),
            brute_force_window_seconds=_env_number(
                "BRUTE_FORCE_WINDOW_SECONDS", DEFAULT_BRUTE_FORCE_WINDOW_SECONDS
            ),
            credential_stuffing_window_seconds=_env_number(
                "CREDENTIAL_STUFFING_WINDOW_SECONDS", DEFAULT_CROSS_SOURCE_WINDOW_SECONDS
            ),
            suppression=Suppression.from_env(),
        )

    def as_facts(self) -> dict[str, Any]:
        """Return the RuleContext facts these settings correspond to."""
        return {
            "brute_force_threshold": self.brute_force_threshold,
            "brute_force_window_seconds": self.brute_force_window_seconds,
            "credential_stuffing_window_seconds": self.credential_stuffing_window_seconds,
            "suppression": self.suppression,
        }
