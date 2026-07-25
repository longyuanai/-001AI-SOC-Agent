"""MITRE ATT&CK pattern registry for AI-SOC-Agent."""

from shared_llm_core.rule_engine import RuleEngine, RuleRegistry

from ai_soc_agent.patterns.base import SOCPattern
from ai_soc_agent.patterns.brute_force import BruteForceBurstRule
from ai_soc_agent.patterns.credential_stuffing import CredentialStuffingRule
from ai_soc_agent.patterns.geo_anomaly import GeoAnomalousLoginRule
from ai_soc_agent.patterns.lateral_movement import LateralMovementRule
from ai_soc_agent.patterns.priv_esc import PrivilegeEscalationRule

ENTRY_POINT_GROUP = "longyuanai.soc_patterns"
PATTERN_TYPES = (
    BruteForceBurstRule,
    GeoAnomalousLoginRule,
    PrivilegeEscalationRule,
    LateralMovementRule,
    CredentialStuffingRule,
)


def register_patterns(registry: RuleRegistry | None = None) -> RuleRegistry:
    """Register every built-in SOC pattern in a v0.5 RuleRegistry."""
    target = RuleRegistry() if registry is None else registry
    for pattern_type in PATTERN_TYPES:
        target.register(pattern_type())
    return target


def build_pattern_engine() -> RuleEngine:
    """Build the RuleEngine used by the SOC correlation pipeline."""
    return RuleEngine(register_patterns())


__all__ = [
    "BruteForceBurstRule",
    "CredentialStuffingRule",
    "ENTRY_POINT_GROUP",
    "GeoAnomalousLoginRule",
    "LateralMovementRule",
    "PATTERN_TYPES",
    "PrivilegeEscalationRule",
    "SOCPattern",
    "build_pattern_engine",
    "register_patterns",
]
