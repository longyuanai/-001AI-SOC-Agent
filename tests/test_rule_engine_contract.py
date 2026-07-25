"""Contract tests proving Phase-2 patterns execute through v0.5 RuleEngine."""

from __future__ import annotations

import json
from pathlib import Path

from shared_llm_core.rule_engine import Rule, RuleContext

from ai_soc_agent.correlator import detect_patterns
from ai_soc_agent.patterns import PATTERN_TYPES, build_pattern_engine, register_patterns

SAMPLES = Path(__file__).parents[1] / "samples" / "mitre"


def test_all_soc_patterns_inherit_frozen_rule_contract() -> None:
    assert len(PATTERN_TYPES) == 5
    assert all(issubclass(pattern_type, Rule) for pattern_type in PATTERN_TYPES)


def test_registry_contains_all_five_pattern_ids() -> None:
    registry = register_patterns()

    assert [rule.id for rule in registry.all()] == [
        "001.mitre.t1110.brute-force-burst",
        "001.mitre.t1078.geo-anomalous-login",
        "001.mitre.t1548.privilege-escalation",
        "001.mitre.t1021.lateral-movement",
        "001.mitre.t1110.004.credential-stuffing",
    ]


def test_rule_engine_executes_selected_pattern() -> None:
    events = [
        json.loads(line)
        for line in (SAMPLES / "T1110.log").read_text(encoding="utf-8").splitlines()
    ]
    engine = build_pattern_engine()

    findings = engine.evaluate(
        RuleContext(subject="203.0.113.45", facts={"events": events}),
        rule_ids=["001.mitre.t1110.brute-force-burst"],
    )

    assert len(findings) == 1
    assert findings[0].metadata["rule_id"] == "001.mitre.t1110.brute-force-burst"


def test_correlator_phase2_path_accepts_injected_rule_engine() -> None:
    class RecordingEngine:
        called = False

        def evaluate(self, ctx: RuleContext) -> list:
            self.called = True
            assert ctx.facts["events"] == ()
            return []

    engine = RecordingEngine()

    assert detect_patterns([], engine=engine) == []
    assert engine.called
