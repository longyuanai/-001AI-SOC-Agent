"""Cross-product correlation host enrichment tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.findings import correlation_host
from ai_soc_agent.patterns import (
    BruteForceBurstRule,
    GeoAnomalousLoginRule,
    PrivilegeEscalationRule,
)

SAMPLES = Path(__file__).parents[1] / "samples" / "mitre"


def _load(name: str) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (SAMPLES / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _finding(rule, sample: str):
    events = _load(sample)
    return rule.evaluate(RuleContext(subject="host-test", facts={"events": events}))[0]


def test_brute_force_finding_host_is_source_ipv4() -> None:
    finding = _finding(BruteForceBurstRule(), "T1110.log")

    assert finding.host == "203.0.113.45"


def test_geo_anomaly_finding_host_is_nonempty_ipv4() -> None:
    finding = _finding(GeoAnomalousLoginRule(), "T1078.log")

    assert finding.host == "198.51.100.20"


def test_privilege_escalation_falls_back_to_event_host() -> None:
    finding = _finding(PrivilegeEscalationRule(), "T1548.log")

    assert finding.host == "10.0.0.15"


def test_correlation_host_rejects_unusable_actor_without_fallback() -> None:
    assert correlation_host({"actor": "service-account", "extra": {}}) is None
