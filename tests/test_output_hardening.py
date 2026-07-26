"""Untrusted input reaching the report and the model reply reaching the CLI."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from click.testing import CliRunner
from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage

from ai_soc_agent.analyzer import (
    AlertAssessment,
    AssessmentError,
    _parse_assessment,
    analyze_events,
)
from ai_soc_agent.cli import cli
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.reporter import render_markdown


def _response(content: str) -> ChatResponse:
    return ChatResponse(
        id="x",
        model="m",
        created=0,
        choices=[
            ChatChoice(
                index=0,
                message=ChatMessage(role="assistant", content=content),
                finish_reason="stop",
            )
        ],
        usage=ChatUsage(),
    )


def _assessment(**overrides) -> AlertAssessment:
    base = {
        "summary": "Brute-force attempt.",
        "severity": "high",
        "confidence": 0.9,
        "attack_pattern": "T1110",
        "recommended_action": "Block IP.",
        "raw_response": {},
    }
    return AlertAssessment(**{**base, **overrides})


def _event(**overrides) -> NormalizedEvent:
    base = {
        "ts": datetime(2026, 7, 23, 22, 1, 14, tzinfo=UTC),
        "actor": "1.2.3.4",
        "action": "ssh_login",
        "target": "root",
        "result": "failure",
        "source": "sshd",
    }
    return NormalizedEvent(**{**base, **overrides})


def test_non_json_reply_raises_a_readable_error() -> None:
    with pytest.raises(AssessmentError, match="did not return JSON"):
        _parse_assessment(_response("I'm sorry, I can't help with that."))


def test_json_array_reply_is_rejected() -> None:
    with pytest.raises(AssessmentError, match="expected a JSON object"):
        _parse_assessment(_response("[1, 2, 3]"))


def test_unknown_severity_falls_back_to_low() -> None:
    reply = json.dumps({"summary": "x", "severity": "catastrophic", "confidence": 0.5})

    assert _parse_assessment(_response(reply)).severity == "low"


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [(1.7, 1.0), (-0.5, 0.0), ("high", 0.0), (None, 0.0)],
)
def test_confidence_is_clamped(supplied: object, expected: float) -> None:
    reply = json.dumps({"summary": "x", "severity": "low", "confidence": supplied})

    assert _parse_assessment(_response(reply)).confidence == expected


def test_cli_reports_a_bad_model_reply_instead_of_a_traceback(tmp_path, monkeypatch) -> None:
    import ai_soc_agent.cli as cli_module

    log = tmp_path / "auth.log"
    log.write_text(
        "Jul 23 22:01:14 mail sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    def _boom(events, router, **kwargs):
        raise AssessmentError("model did not return JSON")

    monkeypatch.setattr(cli_module, "analyze_events", _boom)
    result = CliRunner().invoke(cli, ["analyze", "-i", str(log)])

    assert result.exit_code != 0
    assert "LLM triage failed" in result.output
    assert "Traceback" not in result.output


def test_assessment_discloses_that_it_saw_a_subset(stub_router) -> None:
    stub_router.set_reply(
        {"summary": "x", "severity": "high", "confidence": 0.9, "attack_pattern": "T1110"}
    )
    events = [_event(actor=f"1.2.3.{index}") for index in range(30)]

    assessment = analyze_events(events, stub_router, max_batch=20)

    assert assessment.analyzed_events == 20
    assert assessment.total_events == 30
    assert "20 of 30 events" in assessment.to_markdown()


def test_report_escapes_pipes_in_log_derived_fields() -> None:
    md = render_markdown(
        [_event(target="root | admin", actor="1.2.3.4")],
        _assessment(),
    )

    table_rows = [line for line in md.splitlines() if line.startswith("| 2026")]
    assert len(table_rows) == 1
    # One data row must still have exactly the five declared columns.
    assert table_rows[0].count("|") - table_rows[0].count("\\|") == 6


def test_report_collapses_newlines_in_fields() -> None:
    md = render_markdown([_event(target="root\n| injected | row |")], _assessment())

    assert "| injected" not in md.replace("\\|", "")


def test_report_bounds_a_huge_actor_list() -> None:
    events = [_event(actor=f"10.0.{index // 256}.{index % 256}") for index in range(400)]

    md = render_markdown(events, _assessment())

    stats_line = next(line for line in md.splitlines() if "Unique source IPs" in line)
    assert "Unique source IPs (400)" in stats_line
    assert "more_" in stats_line
    assert len(stats_line) < 1_000


def test_report_sample_table_is_chronological() -> None:
    events = [
        _event(ts=datetime(2026, 7, 23, 22, 5, tzinfo=UTC), target="late"),
        _event(ts=datetime(2026, 7, 23, 22, 1, tzinfo=UTC), target="early"),
    ]

    md = render_markdown(events, _assessment())

    assert md.index("early") < md.index("late")


def test_bare_options_still_route_to_scan() -> None:
    """`python -m ai_soc_agent.cli --json` must keep working."""
    result = CliRunner().invoke(cli, ["--input", '{"source":"sshd","events":[]}', "--json"])

    assert result.exit_code == 0
    assert json.loads(result.output) == {"findings": []}


def test_help_is_not_swallowed_by_the_default_command() -> None:
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "log analysis copilot" in result.output
