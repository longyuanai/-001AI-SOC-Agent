from __future__ import annotations

from pathlib import Path

import pytest
from shared_llm_core.evaluation import EvalCase, run_eval

FIXTURES = Path(__file__).resolve().parents[1] / "evals" / "fixtures"

_CASE_ROWS = (
    ("soc-brute-force", "high", {"scenario": "brute_force"}),
    ("soc-credential-stuffing", "critical", {"scenario": "credential_stuffing"}),
    ("soc-lateral-movement", "high", {"scenario": "lateral_movement"}),
    ("soc-privilege-escalation", "critical", {"scenario": "privilege_escalation"}),
    ("soc-geo-anomaly", "medium", {"scenario": "geo_anomaly"}),
    ("soc-empty-events", "low", {"events": []}),
    ("soc-single-event", "low", {"event_count": 1}),
    ("soc-max-batch-truncated", "high", {"event_count": 25, "max_batch": 20}),
)


def _cases() -> list[EvalCase]:
    return [
        EvalCase(
            id=case_id,
            inputs=inputs,
            expected={
                "required_fields": [
                    "summary",
                    "severity",
                    "confidence",
                    "attack_pattern",
                    "recommended_action",
                ],
                "severity": {
                    "allowed": ["low", "medium", "high", "critical"],
                    "baseline": severity,
                    "max_drift": 0,
                },
                "confidence": {"min": 0.0, "max": 1.0},
            },
        )
        for case_id, severity, inputs in _CASE_ROWS
    ]


def test_golden_set_passes_in_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHARED_LLM_EVAL_MODE", "replay")
    monkeypatch.setenv("SHARED_LLM_EVAL_FIXTURES", str(FIXTURES))

    results = run_eval(_cases())

    assert all(result.passed for result in results), results


def test_golden_set_has_expected_case_count() -> None:
    cases = _cases()

    assert len(cases) >= 8
    assert len({case.id for case in cases}) == len(cases)
    assert {path.stem for path in FIXTURES.glob("*.json")} == {case.id for case in cases}
