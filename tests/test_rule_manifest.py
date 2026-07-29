"""Rule manifest audit and CLI tests for RULE-MANIFEST-001."""

from __future__ import annotations

import json
import tomllib
from dataclasses import replace
from pathlib import Path

from click.testing import CliRunner
from shared_llm_core.finding import FindingSeverity
from shared_llm_core.rule_engine import RuleContext

from ai_soc_agent.cli import cli
from ai_soc_agent.patterns import (
    PATTERN_TYPES,
    RULE_MANIFESTS,
    BruteForceBurstRule,
    CredentialStuffingRule,
    GeoAnomalousLoginRule,
    LateralMovementRule,
    PrivilegeEscalationRule,
    validate_builtin_manifests,
)
from ai_soc_agent.patterns.manifest import resolve_entry_point, validate_manifests

PROJECT_ROOT = Path(__file__).parents[1]


def test_builtin_manifests_cover_all_registered_patterns() -> None:
    assert len(RULE_MANIFESTS) == len(PATTERN_TYPES) == 5
    assert {manifest.id for manifest in RULE_MANIFESTS} == {
        pattern_type.id for pattern_type in PATTERN_TYPES
    }


def test_builtin_manifest_ids_and_entry_point_names_are_unique() -> None:
    ids = [manifest.id for manifest in RULE_MANIFESTS]
    names = [manifest.entry_point_name for manifest in RULE_MANIFESTS]

    assert len(ids) == len(set(ids))
    assert len(names) == len(set(names))


def test_builtin_manifests_have_auditable_mitre_metadata() -> None:
    for manifest in RULE_MANIFESTS:
        assert manifest.status == "stable"
        assert manifest.tactic.startswith("TA")
        assert manifest.technique.startswith("T")
        assert manifest.log_sources
        assert manifest.group_by
        assert manifest.required_fields
        assert all(seconds > 0 for seconds in manifest.window_seconds)
        assert manifest.severity in FindingSeverity


def test_manifest_entry_points_resolve_to_registered_pattern_types() -> None:
    resolved = {
        resolve_entry_point(manifest.entry_point_target) for manifest in RULE_MANIFESTS
    }

    assert resolved == set(PATTERN_TYPES)


def test_pyproject_entry_points_match_manifest_targets() -> None:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    configured = data["tool"]["poetry"]["plugins"]["longyuanai.soc_patterns"]
    expected = {
        manifest.entry_point_name: manifest.entry_point_target
        for manifest in RULE_MANIFESTS
    }

    assert configured == expected


def test_manifest_serialization_is_json_safe_and_stable() -> None:
    item = RULE_MANIFESTS[0].to_dict()

    assert list(item) == [
        "id",
        "title",
        "status",
        "log_sources",
        "tactic",
        "technique",
        "severity",
        "group_by",
        "window_seconds",
        "required_fields",
        "entry_point",
    ]
    assert item["severity"] == "high"
    assert json.loads(json.dumps(item)) == item


def test_builtin_manifest_validation_reports_no_errors() -> None:
    assert validate_builtin_manifests() == ()


def test_manifest_validation_rejects_duplicate_rule_id() -> None:
    duplicate = replace(RULE_MANIFESTS[1], id=RULE_MANIFESTS[0].id)

    errors = validate_manifests(
        (RULE_MANIFESTS[0], duplicate, *RULE_MANIFESTS[2:]),
        PATTERN_TYPES,
    )

    assert any("duplicate manifest id" in error for error in errors)


def test_manifest_validation_rejects_invalid_mitre_identifier() -> None:
    invalid = replace(RULE_MANIFESTS[0], technique="not-a-technique")

    errors = validate_manifests((invalid, *RULE_MANIFESTS[1:]), PATTERN_TYPES)

    assert any("invalid MITRE technique" in error for error in errors)


def test_manifest_validation_rejects_rule_metadata_drift() -> None:
    drifted = replace(RULE_MANIFESTS[0], severity=FindingSeverity.LOW)

    errors = validate_manifests((drifted, *RULE_MANIFESTS[1:]), PATTERN_TYPES)

    assert any("severity differs from rule" in error for error in errors)


def test_rules_list_json_returns_all_manifests() -> None:
    result = CliRunner().invoke(cli, ["rules", "list", "--json"])

    assert result.exit_code == 0
    envelope = json.loads(result.output)
    assert list(envelope) == ["rules"]
    assert len(envelope["rules"]) == 5
    assert envelope["rules"][0]["id"] == BruteForceBurstRule.id


def test_rules_validate_cli_reports_success() -> None:
    result = CliRunner().invoke(cli, ["rules", "validate"])

    assert result.exit_code == 0
    assert result.output.strip() == "5 rule manifest(s) valid"


def _malformed_context() -> RuleContext:
    return RuleContext(subject="malformed", facts={"events": ({"bad": "value"},)})


def test_brute_force_ignores_malformed_input() -> None:
    assert BruteForceBurstRule().evaluate(_malformed_context()) == []


def test_geo_anomaly_ignores_malformed_input() -> None:
    assert GeoAnomalousLoginRule().evaluate(_malformed_context()) == []


def test_priv_esc_ignores_malformed_input() -> None:
    assert PrivilegeEscalationRule().evaluate(_malformed_context()) == []


def test_lateral_movement_ignores_malformed_input() -> None:
    assert LateralMovementRule().evaluate(_malformed_context()) == []


def test_credential_stuffing_ignores_malformed_input() -> None:
    assert CredentialStuffingRule().evaluate(_malformed_context()) == []
