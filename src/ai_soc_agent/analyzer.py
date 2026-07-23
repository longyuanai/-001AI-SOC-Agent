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


def _parse_assessment(resp: ChatResponse) -> AlertAssessment:
    """Parse the LLM's JSON reply into an AlertAssessment."""
    text = resp.choices[0].message.content.strip()
    # Tolerate ```json fences.
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    data = json.loads(text)
    return AlertAssessment(
        summary=str(data.get("summary", "")),
        severity=str(data.get("severity", "low")).lower(),
        confidence=float(data.get("confidence", 0.0)),
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

    batch = events[:max_batch]
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
    return _parse_assessment(resp)