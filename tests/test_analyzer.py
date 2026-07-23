"""Tests for the analyzer with the LLM router stubbed."""

from __future__ import annotations

import json

import pytest

from ai_soc_agent.analyzer import AlertAssessment, analyze_events
from ai_soc_agent.normalizer import NormalizedEvent
from shared_llm_core import ChatRequest, ChatResponse, ChatChoice, ChatMessage, ChatUsage


def _sample_events() -> list[NormalizedEvent]:
    from datetime import datetime

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


def _stub_router(reply_json: dict) -> object:
    """Returns a fake router with .chat() returning a fixed ChatResponse."""
    class FakeRouter:
        def __init__(self, body: dict) -> None:
            self._body = body
            self.calls: list[ChatRequest] = []

        def chat(self, tier, req):  # noqa: ARG002
            self.calls.append(req)
            return ChatResponse(
                id="x",
                model="m",
                created=0,
                choices=[
                    ChatChoice(
                        index=0,
                        message=ChatMessage(
                            role="assistant", content=json.dumps(self._body)
                        ),
                        finish_reason="stop",
                    )
                ],
                usage=ChatUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
            )

    return FakeRouter(reply_json)


def test_analyze_empty_events_returns_low_severity_no_call():
    router = _stub_router({})
    out = analyze_events([], router)
    assert isinstance(out, AlertAssessment)
    assert out.severity == "low"
    assert router.calls == []  # no LLM call when there's nothing to analyze


def test_analyze_parses_json_response():
    reply = {
        "summary": "Brute-force attempt from 1.2.3.4 against root.",
        "severity": "high",
        "confidence": 0.9,
        "attack_pattern": "T1110 - Password Spraying",
        "recommended_action": "Block 1.2.3.4 at the edge firewall.",
    }
    router = _stub_router(reply)
    out = analyze_events(_sample_events(), router)
    assert out.severity == "high"
    assert out.confidence == pytest.approx(0.9)
    assert "Brute-force" in out.summary
    assert router.calls, "expected at least one LLM call"


def test_analyze_strips_json_fences():
    reply = {
        "summary": "x",
        "severity": "low",
        "confidence": 0.5,
        "attack_pattern": "x",
        "recommended_action": "x",
    }
    router = _stub_router(reply)
    # Patch the response to include code fences.
    router.chat = lambda tier, req: ChatResponse(  # type: ignore[assignment]
        id="x",
        model="m",
        created=0,
        choices=[
            ChatChoice(
                index=0,
                message=ChatMessage(role="assistant", content="```json\n" + json.dumps(reply) + "\n```"),
                finish_reason="stop",
            )
        ],
        usage=ChatUsage(),
    )
    out = analyze_events(_sample_events(), router)
    assert out.severity == "low"


def test_analyze_requests_json_object_format():
    router = _stub_router({"summary": "x", "severity": "low", "confidence": 0.0, "attack_pattern": "x", "recommended_action": "x"})
    analyze_events(_sample_events(), router)
    req = router.calls[0]
    assert req.response_format == {"type": "json_object"}
    assert req.messages[0].role == "system"
    assert req.messages[1].role == "user"