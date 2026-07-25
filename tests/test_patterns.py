"""MITRE ATT&CK pattern behavior tests using offline representative logs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.patterns import (
    BruteForceBurstRule,
    CredentialStuffingRule,
    GeoAnomalousLoginRule,
    LateralMovementRule,
    PrivilegeEscalationRule,
)

SAMPLES = Path(__file__).parents[1] / "samples" / "mitre"


def _load(name: str) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (SAMPLES / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _ctx(events: list[dict[str, Any]], **facts: Any) -> RuleContext:
    return RuleContext(subject="test-stream", facts={"events": events, **facts})


def test_brute_force_matches_real_attack_log() -> None:
    assert BruteForceBurstRule().match(_ctx(_load("T1110.log")))


def test_brute_force_ignores_normal_traffic() -> None:
    assert not BruteForceBurstRule().match(_ctx(_load("normal.log")))


def test_brute_force_threshold_boundary() -> None:
    events = _load("T1110.log")
    rule = BruteForceBurstRule()

    assert rule.match(_ctx(events))
    assert not rule.match(_ctx(events[:-1]))


def test_geo_anomaly_matches_real_attack_log() -> None:
    assert GeoAnomalousLoginRule().match(_ctx(_load("T1078.log")))


def test_geo_anomaly_ignores_normal_traffic() -> None:
    assert not GeoAnomalousLoginRule().match(_ctx(_load("normal.log")))


def test_geo_anomaly_threshold_boundary() -> None:
    events = _load("T1078.log")
    rule = GeoAnomalousLoginRule()

    assert rule.match(_ctx(events))
    assert not rule.match(_ctx(events[:1]))


def test_priv_esc_matches_real_attack_log() -> None:
    assert PrivilegeEscalationRule().match(_ctx(_load("T1548.log")))


def test_priv_esc_ignores_normal_traffic() -> None:
    assert not PrivilegeEscalationRule().match(_ctx(_load("normal.log")))


def test_priv_esc_threshold_boundary() -> None:
    events = _load("T1548.log")
    rule = PrivilegeEscalationRule()

    assert rule.match(_ctx(events))
    assert not rule.match(_ctx(events[:-1]))


def test_lateral_movement_matches_real_attack_log() -> None:
    assert LateralMovementRule().match(_ctx(_load("T1021.log")))


def test_lateral_movement_ignores_normal_traffic() -> None:
    assert not LateralMovementRule().match(_ctx(_load("normal.log")))


def test_lateral_movement_threshold_boundary() -> None:
    events = _load("T1021.log")
    rule = LateralMovementRule()

    assert rule.match(_ctx(events))
    assert not rule.match(_ctx(events[:-1]))


def test_credential_stuffing_matches_real_attack_log() -> None:
    assert CredentialStuffingRule().match(_ctx(_load("T1110_004.log")))


def test_credential_stuffing_ignores_normal_traffic() -> None:
    assert not CredentialStuffingRule().match(_ctx(_load("normal.log")))


def test_credential_stuffing_threshold_boundary() -> None:
    events = _load("T1110_004.log")
    rule = CredentialStuffingRule()

    assert rule.match(_ctx(events))
    assert not rule.match(_ctx(events[:-1]))
