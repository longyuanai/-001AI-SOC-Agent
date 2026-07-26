"""Stage-2 analyzer: ask the LLM to triage a small batch of events.

For the v0.1 PoC the analyzer is intentionally tiny:
- Takes up to N events.
- Asks the LLM a structured JSON question.
- Returns one `AlertAssessment` per batch (one per "incident").

We deliberately do NOT do multi-step ReAct yet — that's v0.3 territory. The
single-shot JSON contract is small, predictable, and easy to test.
"""

from __future__ import annotations

import json
import logging
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


logger = logging.getLogger(__name__)

VALID_SEVERITIES = ("low", "medium", "high", "critical")


class AssessmentError(RuntimeError):
    """The model's reply could not be read as an assessment."""


@dataclass(frozen=True)
class AlertAssessment:
    """One incident-level verdict from the LLM."""

    summary: str
    severity: str  # "low" | "medium" | "high" | "critical"
    confidence: float  # 0.0–1.0
    attack_pattern: str  # MITRE-style free text ("SSH brute force", ...)
    recommended_action: str
    raw_response: dict[str, Any]
    analyzed_events: int = 0
    total_events: int = 0

    def to_markdown(self) -> str:
        lines = [
            f"- **Severity**: {self.severity}  ",
            f"  **Confidence**: {self.confidence:.0%}  ",
            f"  **Pattern**: {self.attack_pattern}  ",
            f"  **Action**: {self.recommended_action}  ",
            f"  **Summary**: {self.summary}",
        ]
        if self.total_events > self.analyzed_events:
            lines.append(
                f"  \n  **Scope**: based on {self.analyzed_events} of "
                f"{self.total_events} events"
            )
        return "\n".join(lines)


_SYSTEM_PROMPT = """You are an SOC analyst assistant.
Given a small batch of normalized authentication events, classify the
incident. Respond with strict JSON matching this schema:

{
  "summary": "one-sentence human description",
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": 0.0,
  "attack_pattern": "short MITRE-style label",
  "recommended_action": "one concrete action the analyst can take"
}

Never invent IPs or users. Only reason about events provided. Output JSON only."""


_USER_TEMPLATE = """Events:
{events_json}

Return JSON only."""


def _events_to_prompt(events: list[NormalizedEvent]) -> str:
    payload = [e.to_prompt_dict() for e in events]
    return _USER_TEMPLATE.format(events_json=json.dumps(payload, indent=2))


def _severity(value: Any) -> str:
    """Clamp the model's severity onto the allowed ladder."""
    text = str(value).strip().lower()
    if text in VALID_SEVERITIES:
        return text
    logger.warning("model returned unknown severity %r; treating as 'low'", value)
    return "low"


def _confidence(value: Any) -> float:
    """Clamp the model's confidence into 0.0–1.0."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        logger.warning("model returned non-numeric confidence %r; treating as 0.0", value)
        return 0.0
    if number != number:  # NaN
        return 0.0
    return min(1.0, max(0.0, number))


def _parse_assessment(
    resp: ChatResponse, *, analyzed: int = 0, total: int = 0
) -> AlertAssessment:
    """Parse the LLM's JSON reply into an AlertAssessment.

    This is untrusted model output on the CLI's happy path: a malformed reply
    used to surface as a bare JSONDecodeError traceback.
    """
    try:
        text = resp.choices[0].message.content.strip()
    except (AttributeError, IndexError) as exc:
        raise AssessmentError("model returned no choices") from exc

    # Tolerate ```json fences.
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        preview = text[:200] + ("…" if len(text) > 200 else "")
        raise AssessmentError(
            f"model did not return JSON ({exc.msg} at line {exc.lineno}): {preview}"
        ) from exc
    if not isinstance(data, dict):
        raise AssessmentError(f"model returned {type(data).__name__}, expected a JSON object")

    return AlertAssessment(
        summary=str(data.get("summary", "")),
        severity=_severity(data.get("severity", "low")),
        confidence=_confidence(data.get("confidence", 0.0)),
        attack_pattern=str(data.get("attack_pattern", "")),
        recommended_action=str(data.get("recommended_action", "")),
        raw_response=data,
        analyzed_events=analyzed,
        total_events=total,
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

    batch = events[:max_batch]
    if len(events) > max_batch:
        logger.info(
            "analyzing the first %d of %d events; the verdict does not cover the rest",
            max_batch,
            len(events),
        )
    req = ChatRequest(
        messages=[
            ChatMessage(role="system", content=_SYSTEM_PROMPT),
            ChatMessage(role="user", content=_events_to_prompt(batch)),
        ],
        temperature=0.2,
        max_tokens=400,
        response_format={"type": "json_object"},
    )
    resp: ChatResponse = router.chat(TaskTier.STANDARD, req)
    return _parse_assessment(resp, analyzed=len(batch), total=len(events))