"""Single source of truth for detection thresholds and windows.

Thresholds used to be scattered as literals across the rules, ``correlate()``
and ``cli.scan``, so the same log file produced different findings depending on
which entry point ran it — with nothing saying that was intentional.

There are now exactly two named profiles:

* :func:`detection_facts` — the default, used by one-shot scans (CLI ``scan``
  and the IntegrationGateway adapter), where the caller hands over a bounded
  file or batch and expects every burst in it to be reported.
* :data:`STREAMING_PROFILE` — used by ``correlate()`` behind the ``/ingest``
  API, which sees a continuous firehose and deliberately runs a less twitchy
  brute-force threshold over a longer window.

Any other tuning belongs in the payload, not in a new literal.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from functools import lru_cache
from typing import Any

# Brute force (T1110): failed logins from one IP.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 60

# Privilege escalation (T1548): failed sudo attempts by one user.
PRIV_ESC_THRESHOLD = 3
PRIV_ESC_WINDOW_SECONDS = 120

# Lateral movement (T1021): distinct hosts reached by one user.
LATERAL_MOVEMENT_HOST_THRESHOLD = 3
LATERAL_MOVEMENT_WINDOW_SECONDS = 600

# Geo-anomalous login (T1078): distinct continents for one user.
GEO_ANOMALY_CONTINENT_THRESHOLD = 2
GEO_ANOMALY_WINDOW_SECONDS = 86_400

# Credential stuffing (T1110.004): one credential against many accounts.
CREDENTIAL_STUFFING_USER_THRESHOLD = 3
CREDENTIAL_STUFFING_WINDOW_SECONDS = 300

# Credential stuffing, cross-source mode: one account failing on ssh + vpn + web.
CROSS_SOURCE_MODE = "cross_source"
CREDENTIAL_STUFFING_FAMILIES = frozenset({"ssh", "vpn", "web"})
CREDENTIAL_STUFFING_CROSS_SOURCE_WINDOW_SECONDS = 600

#: Longest lookback any rule needs; bounds how much history must be correlated.
MAX_RULE_WINDOW_SECONDS = max(
    BRUTE_FORCE_WINDOW_SECONDS,
    PRIV_ESC_WINDOW_SECONDS,
    LATERAL_MOVEMENT_WINDOW_SECONDS,
    GEO_ANOMALY_WINDOW_SECONDS,
    CREDENTIAL_STUFFING_WINDOW_SECONDS,
    CREDENTIAL_STUFFING_CROSS_SOURCE_WINDOW_SECONDS,
)

_DEFAULT_FACTS: dict[str, Any] = {
    "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
    "brute_force_window_seconds": BRUTE_FORCE_WINDOW_SECONDS,
    "priv_esc_threshold": PRIV_ESC_THRESHOLD,
    "priv_esc_window_seconds": PRIV_ESC_WINDOW_SECONDS,
    "lateral_movement_host_threshold": LATERAL_MOVEMENT_HOST_THRESHOLD,
    "lateral_movement_window_seconds": LATERAL_MOVEMENT_WINDOW_SECONDS,
    "geo_anomaly_continent_threshold": GEO_ANOMALY_CONTINENT_THRESHOLD,
    "geo_anomaly_window_seconds": GEO_ANOMALY_WINDOW_SECONDS,
    "credential_stuffing_user_threshold": CREDENTIAL_STUFFING_USER_THRESHOLD,
    "credential_stuffing_window_seconds": CREDENTIAL_STUFFING_WINDOW_SECONDS,
    "credential_stuffing_cross_source_window_seconds": (
        CREDENTIAL_STUFFING_CROSS_SOURCE_WINDOW_SECONDS
    ),
}

#: Overrides applied by the streaming ``/ingest`` path. See the module docstring.
STREAMING_PROFILE: dict[str, Any] = {
    "brute_force_threshold": 10,
    "brute_force_window_seconds": 300,
    "credential_stuffing_mode": CROSS_SOURCE_MODE,
}


#: Path segments that mark an HTTP request as an authentication attempt.
DEFAULT_LOGIN_PATH_SEGMENTS = frozenset(
    {
        "auth",
        "authenticate",
        "login",
        "log-in",
        "logon",
        "oauth",
        "session",
        "sessions",
        "signin",
        "sign-in",
        "sso",
        "token",
    }
)

#: Comma-separated extra segments, for deployments whose login route is custom
#: (``j_security_check``, ``identity``, ...). Additive: the defaults always apply.
LOGIN_PATH_SEGMENTS_ENV = "AI_SOC_LOGIN_PATH_SEGMENTS"


@lru_cache(maxsize=8)
def _parse_login_segments(raw: str) -> frozenset[str]:
    extra = {segment.strip().casefold() for segment in raw.split(",")}
    return DEFAULT_LOGIN_PATH_SEGMENTS | {segment for segment in extra if segment}


def login_path_segments() -> frozenset[str]:
    """Return the auth path segments, including any environment additions."""
    return _parse_login_segments(os.environ.get(LOGIN_PATH_SEGMENTS_ENV, ""))


def detection_facts(overrides: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return the shared rule facts, with caller overrides applied on top."""
    facts = dict(_DEFAULT_FACTS)
    if overrides:
        facts.update(overrides)
    return facts
