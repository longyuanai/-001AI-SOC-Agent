"""Every independently matching group must produce its own Finding.

Rules used to ``return`` on the first qualifying window, so a scan reported one
brute-forcing IP no matter how many were attacking. Separately, only
brute_force and credential_stuffing supplied the metadata ``_finding_to_alert``
needs, so the other three patterns were silently dropped between the CLI and
the /alerts API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.config import DetectionConfig, Suppression
from ai_soc_agent.correlator import correlate, detect_patterns
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.patterns import (
    BruteForceBurstRule,
    GeoAnomalousLoginRule,
    LateralMovementRule,
    PrivilegeEscalationRule,
)

START = datetime(2026, 7, 24, 1, 0, tzinfo=UTC)


def _event(
    offset_seconds: int,
    *,
    actor: str,
    action: str = "ssh_login",
    target: str = "root",
    result: str = "failure",
    source: str = "sshd",
    extra: dict[str, Any] | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        ts=START + timedelta(seconds=offset_seconds),
        actor=actor,
        action=action,
        target=target,
        result=result,
        source=source,
        extra=extra or {},
    )


def _ctx(events: list[Any], **facts: Any) -> RuleContext:
    return RuleContext(subject="test-stream", facts={"events": events, **facts})


def test_brute_force_reports_every_attacking_ip() -> None:
    attackers = ["203.0.113.45", "198.51.100.20", "192.0.2.77"]
    events = [
        _event(index * 5, actor=ip)
        for ip in attackers
        for index in range(5)
    ]

    findings = BruteForceBurstRule().evaluate(_ctx(events))

    assert len(findings) == 3
    assert {finding.metadata["actor"] for finding in findings} == set(attackers)


def test_brute_force_emits_one_finding_per_ip_not_per_event() -> None:
    # 40 failures from one IP is one incident, not 36 sliding-window duplicates.
    events = [_event(index * 2, actor="203.0.113.45") for index in range(40)]

    findings = BruteForceBurstRule().evaluate(_ctx(events))

    assert len(findings) == 1


def test_brute_force_escalates_severity_far_past_threshold() -> None:
    modest = [_event(index * 2, actor="203.0.113.45") for index in range(5)]
    sustained = [_event(index, actor="198.51.100.20") for index in range(40)]

    modest_finding = BruteForceBurstRule().evaluate(_ctx(modest))[0]
    sustained_finding = BruteForceBurstRule().evaluate(_ctx(sustained))[0]

    assert modest_finding.severity.value == "high"
    assert sustained_finding.severity.value == "critical"


def test_privilege_escalation_reports_every_user() -> None:
    events = [
        _event(
            index * 10,
            actor=user,
            action="sudo_exec",
            source="linux-audit",
            extra={"user": user, "process": "sudo", "host": "10.0.0.15"},
        )
        for user in ("deploy", "jenkins")
        for index in range(3)
    ]

    findings = PrivilegeEscalationRule().evaluate(_ctx(events))

    assert len(findings) == 2
    assert {finding.metadata["actor"] for finding in findings} == {"deploy", "jenkins"}


def test_lateral_movement_reports_every_user() -> None:
    events = [
        _event(
            index * 30,
            actor=user,
            action="ssh_login",
            target=f"host-{index}",
            result="success",
            extra={"user": user, "destination_host": f"host-{index}"},
        )
        for user in ("operator", "backup")
        for index in range(3)
    ]

    findings = LateralMovementRule().evaluate(_ctx(events))

    assert len(findings) == 2


def test_geo_anomaly_reports_every_user() -> None:
    events = [
        _event(
            index * 3600,
            actor=f"198.51.100.{index}",
            action="okta_login",
            target=user,
            result="success",
            source="okta",
            extra={"user": user, "continent": continent},
        )
        for user in ("analyst@example.test", "admin@example.test")
        for index, continent in enumerate(("NA", "EU"))
    ]

    findings = GeoAnomalousLoginRule().evaluate(_ctx(events))

    assert len(findings) == 2


def test_all_five_rules_supply_alert_metadata() -> None:
    """Missing metadata is why three patterns never reached /alerts."""
    required = {"alert_kind", "actor", "first_seen", "last_seen", "event_count"}
    cases = [
        (
            BruteForceBurstRule(),
            [_event(index * 2, actor="203.0.113.45") for index in range(5)],
            {},
        ),
        (
            PrivilegeEscalationRule(),
            [
                _event(
                    index * 10,
                    actor="deploy",
                    action="sudo_exec",
                    source="linux-audit",
                    extra={"user": "deploy", "process": "sudo"},
                )
                for index in range(3)
            ],
            {},
        ),
        (
            LateralMovementRule(),
            [
                _event(
                    index * 30,
                    actor="operator",
                    target=f"host-{index}",
                    result="success",
                    extra={"user": "operator", "destination_host": f"host-{index}"},
                )
                for index in range(3)
            ],
            {},
        ),
        (
            GeoAnomalousLoginRule(),
            [
                _event(
                    index * 3600,
                    actor=f"198.51.100.{index}",
                    target="analyst@example.test",
                    result="success",
                    source="okta",
                    extra={"user": "analyst@example.test", "continent": continent},
                )
                for index, continent in enumerate(("NA", "EU"))
            ],
            {},
        ),
    ]

    for rule, events, facts in cases:
        findings = rule.evaluate(_ctx(events, **facts))
        assert findings, f"{rule.id} produced no finding"
        for finding in findings:
            missing = required - set(finding.metadata)
            assert not missing, f"{rule.id} missing metadata {missing}"
            assert finding.metadata["actor"], f"{rule.id} has empty actor"


def test_correlate_surfaces_lateral_movement_as_an_alert() -> None:
    """Previously dropped on the floor by _finding_to_alert."""
    events = [
        _event(
            index * 30,
            actor="operator",
            target=f"host-{index}",
            result="success",
            extra={"user": "operator", "destination_host": f"host-{index}"},
        )
        for index in range(3)
    ]

    alerts = correlate(events)

    assert [alert.kind for alert in alerts] == ["lateral_movement"]
    assert alerts[0].actor == "operator"


def test_correlate_reports_multiple_brute_force_actors() -> None:
    events = [
        _event(index * 20, actor=ip)
        for ip in ("203.0.113.45", "198.51.100.20")
        for index in range(10)
    ]

    alerts = correlate(events)

    assert [alert.kind for alert in alerts] == ["brute_force", "brute_force"]
    assert {alert.actor for alert in alerts} == {"203.0.113.45", "198.51.100.20"}


def test_suppression_allowlists_a_scanner_by_address() -> None:
    events = [
        _event(index * 2, actor=ip)
        for ip in ("203.0.113.45", "198.51.100.20")
        for index in range(5)
    ]
    config = DetectionConfig(
        brute_force_threshold=5,
        suppression=Suppression(actors=frozenset({"198.51.100.20"})),
    )

    findings = detect_patterns(events, facts=config.as_facts())

    assert [finding.metadata["actor"] for finding in findings] == ["203.0.113.45"]


def test_suppression_allowlists_a_scanner_network() -> None:
    import ipaddress

    events = [_event(index * 2, actor="10.20.30.40") for index in range(5)]
    config = DetectionConfig(
        brute_force_threshold=5,
        suppression=Suppression(networks=(ipaddress.ip_network("10.20.0.0/16"),)),
    )

    assert detect_patterns(events, facts=config.as_facts()) == []
