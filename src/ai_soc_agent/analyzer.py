"""Stage-2 analyzer: ask the LLM to triage a small batch of events.

For the v0.1 PoC the analyzer is intentionally tiny:
- Takes up to N events.
- Asks the LLM a structured JSON question.
- Returns one `AlertAssessment` per batch (one per "incident").

We deliberately do NOT do multi-step ReAct yet — that's v0.3 territory. The
single-shot JSON contract is small, predictable, and easy to test.

The prompt lives in ``prompts/incident_triage/v1.yml``, not in this file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from shared_llm_core import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    LLMRouter,
)
from shared_llm_core.router import TaskTier

from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.prompts import load_prompt

PROMPT_NAME = "incident_triage"
PROMPT_VERSION = "v1"

_VALID_SEVERITIES = ("low", "medium", "high", "critical")

#: Matches a ```/```json fenced block, which chat models add even when asked not to.
_FENCE = re.compile(
    r"^\s*```(?:json)?\s*(?P<body>.*?)\s*```\s*$", re.DOTALL | re.IGNORECASE
)


class AnalyzerError(RuntimeError):
    """Raised when the LLM reply cannot be read as an incident assessment."""


@dataclass(frozen=True)
class AlertAssessment:
    """One incident-level verdict from the LLM."""

    summary: str
    severity: str  # "low" | "medium" | "high" | "critical"
    confidence: float  # 0.0–1.0
    attack_pattern: str  # MITRE-style free text ("SSH brute force", ...)
    recommended_action: str
    raw_response: dict[str, Any]

    def to_markdown(self) -> str:
        return (
            f"- **Severity**: {self.severity}  \n"
            f"  **Confidence**: {self.confidence:.0%}  \n"
            f"  **Pattern**: {self.attack_pattern}  \n"
            f"  **Action**: {self.recommended_action}  \n"
            f"  **Summary**: {self.summary}"
        )


def _events_to_prompt(events: list[NormalizedEvent]) -> str:
    payload = [event.to_prompt_dict() for event in events]
    template = load_prompt(PROMPT_NAME, PROMPT_VERSION)
    return template.render_user(events_json=json.dumps(payload, indent=2))


def _response_text(resp: ChatResponse) -> str:
    """Pull the assistant text out of a response, or explain what was wrong."""
    choices = getattr(resp, "choices", None) or []
    if not choices:
        raise AnalyzerError("LLM returned no choices")
    content = getattr(getattr(choices[0], "message", None), "content", None)
    if not isinstance(content, str) or not content.strip():
        raise AnalyzerError("LLM returned an empty message")
    text = content.strip()
    fenced = _FENCE.match(text)
    return fenced.group("body").strip() if fenced else text


def _coerce_confidence(value: Any) -> float:
    """Clamp the model's self-reported confidence into the documented 0–1 range."""
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    if confidence != confidence:  # NaN
        return 0.0
    return min(max(confidence, 0.0), 1.0)


def _coerce_severity(value: Any) -> str:
    """Fall back to the least alarming label rather than inventing a new one."""
    severity = str(value).strip().lower()
    return severity if severity in _VALID_SEVERITIES else "low"


def _parse_assessment(resp: ChatResponse) -> AlertAssessment:
    """Parse the LLM's JSON reply into an AlertAssessment.

    Malformed replies raise :class:`AnalyzerError` naming the problem, instead of
    letting a bare ``JSONDecodeError`` or ``AttributeError`` escape to the CLI.
    """
    text = _response_text(resp)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AnalyzerError(
            f"LLM reply was not valid JSON ({exc.msg} at line {exc.lineno}): {text[:200]!r}"
        ) from exc
    if not isinstance(data, dict):
        raise AnalyzerError(f"LLM reply must be a JSON object, got {type(data).__name__}")

    return AlertAssessment(
        summary=str(data.get("summary", "")),
        severity=_coerce_severity(data.get("severity", "low")),
        confidence=_coerce_confidence(data.get("confidence", 0.0)),
        attack_pattern=str(data.get("attack_pattern", "")),
        recommended_action=str(data.get("recommended_action", "")),
        raw_response=data,
    )


def analyze_events(
    events: list[NormalizedEvent],
    router: LLMRouter,
    *,
    max_batch: int = 20,
) -> AlertAssessment:
    """Send the first `max_batch` events to the LLM and return one assessment."""
    if not events:
        return AlertAssessment(
            summary="No events to analyze.",
            severity="low",
            confidence=1.0,
            attack_pattern="none",
            recommended_action="No action needed.",
            raw_response={},
        )

    template = load_prompt(PROMPT_NAME, PROMPT_VERSION)
    batch = events[:max_batch]
    req = ChatRequest(
        messages=[
            ChatMessage(role="system", content=template.system),
            ChatMessage(role="user", content=_events_to_prompt(batch)),
        ],
        temperature=0.2,
        max_tokens=400,
        response_format={"type": "json_object"},
    )
    resp: ChatResponse = router.chat(TaskTier.STANDARD, req)
    return _parse_assessment(resp)
