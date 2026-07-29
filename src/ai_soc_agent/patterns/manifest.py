"""Auditable, Sigma-compatible metadata for built-in SOC rules.

The manifest describes rules; it does not execute them.  The frozen v0.5
``Rule.evaluate()`` contract remains the only detection path.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from importlib import import_module
from typing import Any, Sequence

from shared_llm_core.finding import FindingSeverity

from ai_soc_agent.config import (
    DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,
    DEFAULT_CREDENTIAL_WINDOW_SECONDS,
    DEFAULT_CROSS_SOURCE_WINDOW_SECONDS,
    DEFAULT_GEO_WINDOW_SECONDS,
    DEFAULT_LATERAL_WINDOW_SECONDS,
    DEFAULT_PRIV_ESC_WINDOW_SECONDS,
)

_VALID_STATUSES = frozenset({"stable", "experimental", "deprecated", "test"})
_TACTIC_PATTERN = re.compile(r"TA\d{4}")
_TECHNIQUE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass(frozen=True, slots=True)
class RuleManifest:
    """Read-only metadata for one executable SOC pattern."""

    id: str
    title: str
    status: str
    log_sources: tuple[str, ...]
    tactic: str
    technique: str
    severity: FindingSeverity
    group_by: tuple[str, ...]
    window_seconds: tuple[float, ...]
    required_fields: tuple[str, ...]
    entry_point_name: str
    entry_point_target: str

    def to_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-safe representation for audit tooling."""
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "log_sources": list(self.log_sources),
            "tactic": self.tactic,
            "technique": self.technique,
            "severity": self.severity.value,
            "group_by": list(self.group_by),
            "window_seconds": list(self.window_seconds),
            "required_fields": list(self.required_fields),
            "entry_point": {
                "name": self.entry_point_name,
                "target": self.entry_point_target,
            },
        }


RULE_MANIFESTS = (
    RuleManifest(
        id="001.mitre.t1110.brute-force-burst",
        title="Brute force burst",
        status="stable",
        log_sources=("sshd", "evtx", "nginx", "okta"),
        tactic="TA0006",
        technique="T1110",
        severity=FindingSeverity.HIGH,
        group_by=("actor",),
        window_seconds=(DEFAULT_BRUTE_FORCE_WINDOW_SECONDS,),
        required_fields=("ts", "actor", "action", "result"),
        entry_point_name="001.brute_force",
        entry_point_target=(
            "ai_soc_agent.patterns.brute_force:BruteForceBurstRule"
        ),
    ),
    RuleManifest(
        id="001.mitre.t1078.geo-anomalous-login",
        title="Geographically anomalous login",
        status="stable",
        log_sources=("sshd", "evtx", "nginx", "okta"),
        tactic="TA0001",
        technique="T1078",
        severity=FindingSeverity.HIGH,
        group_by=("user",),
        window_seconds=(DEFAULT_GEO_WINDOW_SECONDS,),
        required_fields=("ts", "target", "result", "extra.continent"),
        entry_point_name="001.geo_anomaly",
        entry_point_target=(
            "ai_soc_agent.patterns.geo_anomaly:GeoAnomalousLoginRule"
        ),
    ),
    RuleManifest(
        id="001.mitre.t1548.privilege-escalation",
        title="Privilege escalation attempts",
        status="stable",
        log_sources=("sshd", "evtx"),
        tactic="TA0004",
        technique="T1548",
        severity=FindingSeverity.HIGH,
        group_by=("user",),
        window_seconds=(DEFAULT_PRIV_ESC_WINDOW_SECONDS,),
        required_fields=("ts", "actor", "action", "result"),
        entry_point_name="001.priv_esc",
        entry_point_target=(
            "ai_soc_agent.patterns.priv_esc:PrivilegeEscalationRule"
        ),
    ),
    RuleManifest(
        id="001.mitre.t1021.lateral-movement",
        title="Lateral movement",
        status="stable",
        log_sources=("sshd", "evtx", "okta"),
        tactic="TA0008",
        technique="T1021",
        severity=FindingSeverity.HIGH,
        group_by=("user",),
        window_seconds=(DEFAULT_LATERAL_WINDOW_SECONDS,),
        required_fields=("ts", "action", "result", "target"),
        entry_point_name="001.lateral_movement",
        entry_point_target=(
            "ai_soc_agent.patterns.lateral_movement:LateralMovementRule"
        ),
    ),
    RuleManifest(
        id="001.mitre.t1110.004.credential-stuffing",
        title="Credential stuffing",
        status="stable",
        log_sources=("sshd", "evtx", "nginx", "okta"),
        tactic="TA0006",
        technique="T1110.004",
        severity=FindingSeverity.HIGH,
        group_by=("credential_fingerprint", "user"),
        window_seconds=(
            DEFAULT_CREDENTIAL_WINDOW_SECONDS,
            DEFAULT_CROSS_SOURCE_WINDOW_SECONDS,
        ),
        required_fields=("ts", "result", "user"),
        entry_point_name="001.credential_stuffing",
        entry_point_target=(
            "ai_soc_agent.patterns.credential_stuffing:CredentialStuffingRule"
        ),
    ),
)


def resolve_entry_point(target: str) -> Any:
    """Resolve a ``module:qualified_name`` entry-point target."""
    module_name, separator, qualified_name = target.partition(":")
    if not separator or not module_name or not qualified_name:
        raise ValueError(f"invalid entry-point target: {target!r}")
    value: Any = import_module(module_name)
    for part in qualified_name.split("."):
        value = getattr(value, part)
    return value


def validate_manifests(
    manifests: Sequence[RuleManifest],
    pattern_types: Sequence[type[Any]],
) -> tuple[str, ...]:
    """Return deterministic audit errors without mutating the rule registry."""
    errors: list[str] = []
    manifest_ids = [manifest.id for manifest in manifests]
    rule_ids = [pattern_type.id for pattern_type in pattern_types]

    for rule_id, count in Counter(manifest_ids).items():
        if count > 1:
            errors.append(f"duplicate manifest id: {rule_id}")
    for name, count in Counter(
        manifest.entry_point_name for manifest in manifests
    ).items():
        if count > 1:
            errors.append(f"duplicate entry-point name: {name}")
    for rule_id, count in Counter(rule_ids).items():
        if count > 1:
            errors.append(f"duplicate registered rule id: {rule_id}")

    manifest_by_id = {manifest.id: manifest for manifest in manifests}
    rule_by_id = {pattern_type.id: pattern_type for pattern_type in pattern_types}
    for rule_id in sorted(rule_by_id.keys() - manifest_by_id.keys()):
        errors.append(f"missing manifest for registered rule: {rule_id}")
    for rule_id in sorted(manifest_by_id.keys() - rule_by_id.keys()):
        errors.append(f"manifest has no registered rule: {rule_id}")

    for manifest in manifests:
        label = manifest.id
        if manifest.status not in _VALID_STATUSES:
            errors.append(f"{label}: invalid status {manifest.status!r}")
        if _TACTIC_PATTERN.fullmatch(manifest.tactic) is None:
            errors.append(f"{label}: invalid MITRE tactic {manifest.tactic!r}")
        if _TECHNIQUE_PATTERN.fullmatch(manifest.technique) is None:
            errors.append(
                f"{label}: invalid MITRE technique {manifest.technique!r}"
            )
        if not manifest.title.strip():
            errors.append(f"{label}: title must not be empty")
        if not manifest.log_sources:
            errors.append(f"{label}: log_sources must not be empty")
        if not manifest.group_by:
            errors.append(f"{label}: group_by must not be empty")
        if not manifest.required_fields:
            errors.append(f"{label}: required_fields must not be empty")
        if not manifest.window_seconds or any(
            seconds <= 0 for seconds in manifest.window_seconds
        ):
            errors.append(f"{label}: window_seconds must contain positive values")

        pattern_type = rule_by_id.get(manifest.id)
        if pattern_type is None:
            continue
        if pattern_type.tactic != manifest.tactic:
            errors.append(f"{label}: tactic differs from rule")
        if pattern_type.technique != manifest.technique:
            errors.append(f"{label}: technique differs from rule")
        if pattern_type.severity_default != manifest.severity:
            errors.append(f"{label}: severity differs from rule")
        try:
            resolved = resolve_entry_point(manifest.entry_point_target)
        except (AttributeError, ImportError, ValueError) as exc:
            errors.append(f"{label}: entry point does not resolve: {exc}")
        else:
            if resolved is not pattern_type:
                errors.append(f"{label}: entry point resolves to a different rule")

    return tuple(errors)


__all__ = [
    "RULE_MANIFESTS",
    "RuleManifest",
    "resolve_entry_point",
    "validate_manifests",
]
