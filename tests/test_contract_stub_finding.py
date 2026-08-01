"""Direct drift checks for the fallback v0.5 Finding contract stub."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest


def _stub_module():
    path = Path(__file__).parent / "_contract_stub" / "shared_llm_core" / "finding.py"
    name = "_ai_soc_contract_stub_finding"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_stub_finding_description_is_optional_and_id_is_generated() -> None:
    stub = _stub_module()
    finding = stub.Finding(
        id="",
        source=stub.FindingSource.SOC,
        severity=stub.FindingSeverity.HIGH,
        confidence=0.8,
        title="test",
    )

    assert finding.id
    assert finding.description == ""


def test_stub_finding_sources_match_frozen_v05_contract() -> None:
    stub = _stub_module()

    assert {source.value for source in stub.FindingSource} == {
        "001",
        "002",
        "003",
        "004",
        "005",
        "006",
        "external",
    }


def test_stub_finding_round_trip_keeps_all_frozen_fields() -> None:
    stub = _stub_module()
    finding = stub.Finding(
        id="finding-1",
        source=stub.FindingSource.SOC,
        severity=stub.FindingSeverity.MEDIUM,
        confidence=0.7,
        title="test",
        cve="CVE-2026-0001",
        ts=datetime(2026, 8, 1, tzinfo=UTC),
        evidence=("evidence",),
        related=("finding-0",),
        tags=frozenset({"soc"}),
        metadata={"key": "value"},
    )
    payload = {**finding.to_dict(), "future_field": True}

    assert stub.Finding.from_dict(payload) == finding


def test_stub_finding_validates_confidence_range() -> None:
    stub = _stub_module()

    with pytest.raises(ValueError, match="confidence"):
        stub.Finding(
            id="",
            source=stub.FindingSource.SOC,
            severity=stub.FindingSeverity.HIGH,
            confidence=1.1,
            title="test",
        )
