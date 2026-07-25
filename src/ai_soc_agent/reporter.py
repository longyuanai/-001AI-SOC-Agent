"""Markdown report renderer for one incident's worth of events."""

from __future__ import annotations

from datetime import datetime

from ai_soc_agent.analyzer import AlertAssessment
from ai_soc_agent.normalizer import NormalizedEvent


def render_markdown(
    events: list[NormalizedEvent],
    assessment: AlertAssessment,
    *,
    source_path: str = "",
) -> str:
    """Render a Markdown incident report."""
    lines: list[str] = []
    lines.append("# SOC Incident Report")
    lines.append("")
    lines.append(f"_Generated at {datetime.now().isoformat(timespec='seconds')}_")
    if source_path:
        lines.append(f"_Source: `{source_path}`_")
    lines.append("")

    # Top section — assessment.
    lines.append("## Assessment")
    lines.append("")
    lines.append(assessment.to_markdown())
    lines.append("")

    # Stats.
    total = len(events)
    failures = sum(1 for e in events if e.result == "failure")
    successes = sum(1 for e in events if e.result == "success")
    unique_actors = sorted({e.actor for e in events})
    unique_targets = sorted({e.target for e in events})

    lines.append("## Event Stats")
    lines.append("")
    lines.append(f"- Total events: **{total}**")
    lines.append(f"- Failed: **{failures}**, Successful: **{successes}**")
    lines.append(f"- Unique source IPs: {', '.join(unique_actors) or '_none_'}")
    lines.append(f"- Targeted users: {', '.join(unique_targets) or '_none_'}")
    lines.append("")

    # First N raw events.
    lines.append("## Sample Events (first 10)")
    lines.append("")
    lines.append("| Timestamp | Source IP | Action | Target | Result |")
    lines.append("|-----------|-----------|--------|--------|--------|")
    for e in events[:10]:
        cells = (
            e.ts.isoformat(timespec="seconds"),
            e.actor,
            e.action,
            e.target,
            e.result,
        )
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")

    return "\n".join(lines)