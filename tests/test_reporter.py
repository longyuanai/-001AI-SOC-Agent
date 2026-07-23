"""Tests for the Markdown reporter."""

from __future__ import annotations

from datetime import datetime

from ai_soc_agent.analyzer import AlertAssessment
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.reporter import render_markdown


def _event(result: str = "failure", actor: str = "1.2.3.4", target: str = "root") -> NormalizedEvent:
    return NormalizedEvent(
        ts=datetime(2026, 7, 23, 22, 1, 14),
        actor=actor,
        action="ssh_login",
        target=target,
        result=result,
        source="sshd",
        raw="",
    )


def _assessment() -> AlertAssessment:
    return AlertAssessment(
        summary="Brute-force attempt.",
        severity="high",
        confidence=0.9,
        attack_pattern="T1110",
        recommended_action="Block IP.",
        raw_response={},
    )


def test_render_markdown_contains_heading_and_assessment():
    md = render_markdown([_event()], _assessment(), source_path="auth.log")
    assert "# SOC Incident Report" in md
    assert "auth.log" in md
    assert "**Severity**: high" in md
    assert "T1110" in md
    assert "Brute-force" in md


def test_render_markdown_event_stats():
    events = [
        _event("failure", "1.2.3.4", "root"),
        _event("failure", "1.2.3.4", "admin"),
        _event("success", "5.6.7.8", "alice"),
    ]
    md = render_markdown(events, _assessment())
    assert "Total events: **3**" in md
    assert "Failed: **2**" in md
    assert "Successful: **1**" in md
    assert "1.2.3.4" in md
    assert "5.6.7.8" in md


def test_render_markdown_caps_sample_table_at_10():
    events = [_event() for _ in range(25)]
    md = render_markdown(events, _assessment())
    # Count rows in the sample table (lines starting with `|`).
    table_rows = [ln for ln in md.splitlines() if ln.startswith("| ") and "Timestamp" not in ln]
    assert len(table_rows) == 10