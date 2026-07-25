"""Tests for the analyzer with the LLM router stubbed.

After the v0.1-contract §5 refactor, ``StubRouter`` lives in
``tests/conftest.py`` and is injected via the ``stub_router`` fixture.
"""

from __future__ import annotations

import json
from datetime import datetime

import pytest
from shared_llm_core import ChatChoice, ChatMessage, ChatResponse, ChatUsage

from ai_soc_agent.analyzer import (
    PROMPT_NAME,
    PROMPT_VERSION,
    AlertAssessment,
    AnalyzerError,
    analyze_events,
)
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.prompts import load_prompt


def _sample_events() -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            ts=datetime(2026, 7, 23, 22, 1, 14),
            actor="1.2.3.4",
            action="ssh_login",
            target="root",
            result="failure",
            source="sshd",
            raw="",
        )
    ]


def test_analyze_empty_events_returns_low_severity_no_call(stub_router):
    out = analyze_events([], stub_router)
    assert isinstance(out, AlertAssessment)
    assert out.severity == "low"
    assert stub_router.calls == []  # no LLM call when there's nothing to analyze


def test_analyze_parses_json_response(stub_router):
    reply = {
        "summary": "Brute-force attempt from 1.2.3.4 against root.",
        "severity": "high",
        "confidence": 0.9,
        "attack_pattern": "T1110 - Password Spraying",
        "recommended_action": "Block 1.2.3.4 at the edge firewall.",
    }
    stub_router.set_reply(reply)
    out = analyze_events(_sample_events(), stub_router)
    assert out.severity == "high"
    assert out.confidence == pytest.approx(0.9)
    assert "Brute-force" in out.summary
    assert stub_router.calls, "expected at least one LLM call"


def test_analyze_strips_json_fences(stub_router):
    reply = {
        "summary": "x",
        "severity": "low",
        "confidence": 0.5,
        "attack_pattern": "x",
        "recommended_action": "x",
    }
    # Patch the response to include code fences.
    def fenced_chat(tier, req):  # noqa: ARG001
        return ChatResponse(
            id="x",
            model="m",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(
                        role="assistant",
                        content="```json\n" + json.dumps(reply) + "\n```",
                    ),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(),
        )

    stub_router.chat = fenced_chat  # type: ignore[assignment]
    out = analyze_events(_sample_events(), stub_router)
    assert out.severity == "low"


def test_analyze_requests_json_object_format(stub_router):
    stub_router.set_reply(
        {"summary": "x", "severity": "low", "confidence": 0.0,
         "attack_pattern": "x", "recommended_action": "x"}
    )
    analyze_events(_sample_events(), stub_router)
    req = stub_router.calls[0]
    assert req.response_format == {"type": "json_object"}
    assert req.messages[0].role == "system"
    assert req.messages[1].role == "user"


# ---- NEW tests added for v0.1-contract §5 (count ≥ 15) ----


def test_stub_router_fixture_returns_fresh_instance(stub_router):
    """Two invocations of the fixture must be independent."""
    from tests.conftest import StubRouter  # type: ignore

    assert isinstance(stub_router, StubRouter)
    stub_router.set_reply({"a": 1})
    assert stub_router.reply == {"a": 1}


def test_stub_router_records_each_chat_call(stub_router):
    """Calls list is appended on every chat() invocation."""
    stub_router.set_reply({"summary": "x", "severity": "low", "confidence": 0.0,
                           "attack_pattern": "x", "recommended_action": "x"})
    analyze_events(_sample_events(), stub_router)
    analyze_events(_sample_events(), stub_router)
    assert len(stub_router.calls) == 2


def test_stub_router_with_factory(stub_router_with):
    """The factory fixture should yield independent stubs per call."""
    a = stub_router_with({"severity": "high"})
    b = stub_router_with({"severity": "low"})
    a.set_reply({"summary": "A", "severity": "high", "confidence": 1.0,
                 "attack_pattern": "x", "recommended_action": "x"})
    b.set_reply({"summary": "B", "severity": "low", "confidence": 0.0,
                 "attack_pattern": "x", "recommended_action": "x"})
    assert a is not b
    assert a.reply["severity"] == "high"
    assert b.reply["severity"] == "low"


def test_analyze_handles_low_confidence_response(stub_router):
    """Low-confidence LLM reply still parses and surfaces as medium severity."""
    stub_router.set_reply({
        "summary": "uncertain event",
        "severity": "medium",
        "confidence": 0.42,
        "attack_pattern": "unknown",
        "recommended_action": "monitor",
    })
    out = analyze_events(_sample_events(), stub_router)
    assert out.severity == "medium"
    assert out.confidence == pytest.approx(0.42)


# ---- Malformed-LLM-reply handling ----


def _reply_with(content):
    def chat(tier, req):  # noqa: ARG001
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

    return chat


def test_non_json_reply_raises_analyzer_error(stub_router):
    """A bare JSONDecodeError used to reach the CLI as an unhandled traceback."""
    stub_router.chat = _reply_with("I'm afraid I can't do that.")  # type: ignore[assignment]

    with pytest.raises(AnalyzerError, match="not valid JSON"):
        analyze_events(_sample_events(), stub_router)


def test_json_array_reply_raises_analyzer_error(stub_router):
    stub_router.chat = _reply_with('["not", "an", "object"]')  # type: ignore[assignment]

    with pytest.raises(AnalyzerError, match="must be a JSON object"):
        analyze_events(_sample_events(), stub_router)


def test_empty_reply_raises_analyzer_error(stub_router):
    stub_router.chat = _reply_with("   ")  # type: ignore[assignment]

    with pytest.raises(AnalyzerError, match="empty message"):
        analyze_events(_sample_events(), stub_router)


def test_null_content_raises_analyzer_error(stub_router):
    stub_router.chat = _reply_with(None)  # type: ignore[assignment]

    with pytest.raises(AnalyzerError, match="empty message"):
        analyze_events(_sample_events(), stub_router)


def test_response_without_choices_raises_analyzer_error(stub_router):
    def chat(tier, req):  # noqa: ARG001
        return ChatResponse(id="x", model="m", created=0, choices=[], usage=ChatUsage())

    stub_router.chat = chat  # type: ignore[assignment]

    with pytest.raises(AnalyzerError, match="no choices"):
        analyze_events(_sample_events(), stub_router)


def test_unknown_severity_falls_back_to_low(stub_router):
    stub_router.set_reply(
        {
            "summary": "x",
            "severity": "apocalyptic",
            "confidence": 0.5,
            "attack_pattern": "x",
            "recommended_action": "x",
        }
    )

    assert analyze_events(_sample_events(), stub_router).severity == "low"


def test_out_of_range_confidence_is_clamped(stub_router):
    stub_router.set_reply(
        {
            "summary": "x",
            "severity": "high",
            "confidence": 42,
            "attack_pattern": "x",
            "recommended_action": "x",
        }
    )

    assert analyze_events(_sample_events(), stub_router).confidence == 1.0


def test_non_numeric_confidence_becomes_zero(stub_router):
    stub_router.set_reply(
        {
            "summary": "x",
            "severity": "high",
            "confidence": "very sure",
            "attack_pattern": "x",
            "recommended_action": "x",
        }
    )

    assert analyze_events(_sample_events(), stub_router).confidence == 0.0


def test_system_prompt_comes_from_the_yaml_template(stub_router):
    stub_router.set_reply(
        {
            "summary": "x",
            "severity": "low",
            "confidence": 0.0,
            "attack_pattern": "x",
            "recommended_action": "x",
        }
    )
    analyze_events(_sample_events(), stub_router)

    template = load_prompt(PROMPT_NAME, PROMPT_VERSION)
    assert stub_router.calls[0].messages[0].content == template.system
