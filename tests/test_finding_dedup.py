"""Stable Finding fingerprint and adapter suppression tests for DEDUP-001."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

from click.testing import CliRunner
from shared_llm_core.finding import Finding, FindingSeverity, FindingSource

from ai_soc_agent.adapter import SOCProductAdapter
from ai_soc_agent.cli import cli, scan_payload
from ai_soc_agent.dedup import FindingDeduplicator

NOW = datetime(2026, 7, 29, 13, 0, tzinfo=UTC)


def _failed_lines(ip: str = "203.0.113.45") -> list[str]:
    return [
        (
            f"Jul 29 13:00:{index:02d} soc-host sshd[{1200 + index}]: "
            f"Failed password for root from {ip} port {51000 + index} ssh2"
        )
        for index in range(5)
    ]


def _payload(ip: str = "203.0.113.45") -> dict:
    return {"source": "sshd", "events": _failed_lines(ip)}


def _finding(fingerprint: str | None) -> Finding:
    metadata = {} if fingerprint is None else {"fingerprint": fingerprint}
    return Finding(
        id="",
        source=FindingSource.SOC,
        severity=FindingSeverity.HIGH,
        confidence=0.9,
        title="test finding",
        metadata=metadata,
    )


def _collect(adapter: SOCProductAdapter, payload: dict) -> list[Finding]:
    async def collect() -> list[Finding]:
        return [finding async for finding in adapter.scan(payload)]

    return asyncio.run(collect())


def test_pattern_finding_contains_stable_fingerprint() -> None:
    finding = scan_payload(_payload())["findings"][0]

    assert finding["metadata"]["fingerprint"].startswith("soc:")


def test_repeated_scan_keeps_fingerprint_but_not_uuid() -> None:
    first = scan_payload(_payload())["findings"][0]
    second = scan_payload(_payload())["findings"][0]

    assert first["id"] != second["id"]
    assert first["metadata"]["fingerprint"] == second["metadata"]["fingerprint"]


def test_fingerprint_changes_for_different_actor() -> None:
    first = scan_payload(_payload("203.0.113.45"))["findings"][0]
    second = scan_payload(_payload("198.51.100.45"))["findings"][0]

    assert first["metadata"]["fingerprint"] != second["metadata"]["fingerprint"]


def test_fingerprint_changes_for_different_window_start() -> None:
    first_payload = _payload()
    second_payload = {
        "source": "sshd",
        "events": [line.replace("13:00:", "14:00:") for line in _failed_lines()],
    }

    first = scan_payload(first_payload)["findings"][0]
    second = scan_payload(second_payload)["findings"][0]

    assert first["metadata"]["fingerprint"] != second["metadata"]["fingerprint"]


def test_deduplicator_accepts_first_and_suppresses_repeat() -> None:
    deduplicator = FindingDeduplicator(clock=lambda: NOW)
    finding = _finding("soc:repeat")

    assert deduplicator.accept(finding).accepted
    decision = deduplicator.accept(finding)
    assert not decision.accepted
    assert decision.reason == "cooldown"


def test_deduplicator_accepts_again_after_cooldown() -> None:
    current = [NOW]
    deduplicator = FindingDeduplicator(
        cooldown=timedelta(minutes=5),
        clock=lambda: current[0],
    )
    finding = _finding("soc:repeat")
    assert deduplicator.accept(finding).accepted

    current[0] += timedelta(minutes=5)

    assert deduplicator.accept(finding).accepted


def test_deduplicator_capacity_is_bounded() -> None:
    deduplicator = FindingDeduplicator(
        max_entries=2,
        clock=lambda: NOW,
    )

    deduplicator.accept(_finding("soc:one"))
    deduplicator.accept(_finding("soc:two"))
    deduplicator.accept(_finding("soc:three"))

    assert len(deduplicator) == 2
    assert deduplicator.fingerprints() == ("soc:three", "soc:two")


def test_finding_without_fingerprint_is_not_suppressed() -> None:
    deduplicator = FindingDeduplicator(clock=lambda: NOW)
    finding = _finding(None)

    first = deduplicator.accept(finding)
    second = deduplicator.accept(finding)

    assert first.accepted and second.accepted
    assert second.reason == "missing_fingerprint"
    assert len(deduplicator) == 0


def test_persistent_adapter_suppresses_repeated_scan() -> None:
    adapter = SOCProductAdapter()

    assert len(_collect(adapter, _payload())) == 1
    assert _collect(adapter, _payload()) == []


def test_new_adapter_has_isolated_suppression_state() -> None:
    assert len(_collect(SOCProductAdapter(), _payload())) == 1
    assert len(_collect(SOCProductAdapter(), _payload())) == 1


def test_cli_repeated_scans_remain_complete_and_stateless() -> None:
    runner = CliRunner()
    args = ["scan", "--input", json.dumps(_payload()), "--json"]

    first = json.loads(runner.invoke(cli, args).output)
    second = json.loads(runner.invoke(cli, args).output)

    assert len(first["findings"]) == 1
    assert len(second["findings"]) == 1
    assert (
        first["findings"][0]["metadata"]["fingerprint"]
        == second["findings"][0]["metadata"]["fingerprint"]
    )


def test_deduplicator_rejects_invalid_configuration() -> None:
    for kwargs in (
        {"max_entries": 0},
        {"cooldown": timedelta(0)},
    ):
        try:
            FindingDeduplicator(**kwargs)
        except ValueError:
            pass
        else:
            raise AssertionError(f"configuration should fail: {kwargs}")
