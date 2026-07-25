"""Tests for the in-process v0.5 IntegrationGateway adapter."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from click.testing import CliRunner
from shared_llm_core.finding import Finding, FindingSeverity, FindingSource

from ai_soc_agent import SOCProductAdapter
from ai_soc_agent.cli import cli


def _failed_lines(count: int = 5, ip: str = "203.0.113.45") -> list[str]:
    return [
        (
            f"Jul 24 01:00:{index:02d} soc-host sshd[{1200 + index}]: "
            f"Failed password for root from {ip} port {51000 + index} ssh2"
        )
        for index in range(count)
    ]


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": "sshd",
        "events": _failed_lines(),
    }
    payload.update(overrides)
    return payload


def _scan(payload: dict[str, Any]) -> list[Finding]:
    async def collect() -> list[Finding]:
        return [finding async for finding in SOCProductAdapter().scan(payload)]

    return asyncio.run(collect())


def test_adapter_source_is_soc() -> None:
    assert SOCProductAdapter().source is FindingSource.SOC


def test_adapter_health_returns_expected_product_status() -> None:
    assert SOCProductAdapter().health() == {
        "status": "ok",
        "product": "001-soc",
        "version": "0.5.0",
    }


def test_adapter_scan_produces_a_finding() -> None:
    findings = _scan(_payload())

    assert len(findings) == 1
    assert isinstance(findings[0], Finding)


def test_adapter_finding_source_is_soc() -> None:
    finding = _scan(_payload())[0]

    assert finding.source is FindingSource.SOC


def test_adapter_finding_host_comes_from_payload() -> None:
    finding = _scan(_payload(events=_failed_lines(ip="198.51.100.23")))[0]

    assert finding.host == "198.51.100.23"


def test_adapter_scan_empty_events_returns_no_findings() -> None:
    assert _scan({"source": "sshd", "events": []}) == []


def test_adapter_evidence_contains_original_event() -> None:
    event = {
        "ts": "2026-07-24T01:00:00+00:00",
        "actor": "192.0.2.44",
        "action": "ssh_login",
        "target": "root",
        "result": "failure",
        "source": "sshd",
        "extra": {"port": 51000, "auth_method": "password"},
    }

    finding = _scan(
        {
            "source": "sshd",
            "events": [event],
            "brute_force_threshold": 1,
        }
    )[0]

    assert str(event) in finding.evidence


def test_adapter_evidence_does_not_grow_with_unrelated_events() -> None:
    """Evidence must describe the match, not restate the whole submission."""
    attack = _failed_lines(5)
    noise = [
        (
            f"Jul 24 02:00:{index % 60:02d} soc-host sshd[{2000 + index}]: "
            f"Accepted password for alice from 192.0.2.{index % 250} port 22 ssh2"
        )
        for index in range(200)
    ]

    finding = _scan({"source": "sshd", "events": [*attack, *noise]})[0]

    assert len(finding.evidence) == len(attack)
    assert all("Failed password" in item for item in finding.evidence)


def test_adapter_payload_without_events_returns_no_findings() -> None:
    assert _scan({"source": "sshd"}) == []


def test_adapter_finding_severity_and_confidence_are_valid() -> None:
    finding = _scan(_payload())[0]

    assert finding.severity is FindingSeverity.HIGH
    assert 0.0 <= finding.confidence <= 1.0


def test_adapter_finding_id_is_nonempty_uuid() -> None:
    finding = _scan(_payload())[0]

    assert finding.id
    assert uuid.UUID(finding.id).version == 4


def test_cli_scan_envelope_remains_adapter_compatible() -> None:
    payload = _payload()

    result = CliRunner().invoke(
        cli,
        ["scan", "--input", json.dumps(payload), "--json"],
    )

    assert result.exit_code == 0
    envelope = json.loads(result.output)
    assert list(envelope) == ["findings"]
    assert envelope["findings"][0]["host"] == "203.0.113.45"
    assert "source" not in envelope["findings"][0]
