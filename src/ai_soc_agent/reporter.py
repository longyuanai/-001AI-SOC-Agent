"""Markdown report renderer for one incident's worth of events."""

from __future__ import annotations

from datetime import UTC, datetime

from ai_soc_agent.analyzer import AlertAssessment
from ai_soc_agent.normalizer import NormalizedEvent

SAMPLE_ROWS = 10
MAX_LISTED_VALUES = 25


def _cell(value: object) -> str:
    """Escape a value for use inside a Markdown table cell.

    Log fields are attacker-influenced: a username or request path containing a
    pipe or newline used to break the table apart or inject extra rows.
    """
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return " ".join(text.split())


def _listed(values: list[str]) -> str:
    """Render a bounded, comma-separated list."""
    if not values:
        return "_none_"
    shown = [_cell(value) for value in values[:MAX_LISTED_VALUES]]
    remainder = len(values) - len(shown)
    if remainder > 0:
        shown.append(f"_+{remainder} more_")
    return ", ".join(shown)


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
    lines.append(f"_Generated at {datetime.now(UTC).isoformat(timespec='seconds')}_")
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
    lines.append(f"- Unique source IPs ({len(unique_actors)}): {_listed(unique_actors)}")
    lines.append(f"- Targeted users ({len(unique_targets)}): {_listed(unique_targets)}")
    lines.append("")

    # Earliest events in time order: parse order is not chronological once
    # several sources are merged.
    lines.append(f"## Sample Events (first {SAMPLE_ROWS})")
    lines.append("")
    lines.append("| Timestamp | Source IP | Action | Target | Result |")
    lines.append("|-----------|-----------|--------|--------|--------|")
    for e in sorted(events, key=lambda event: event.ts)[:SAMPLE_ROWS]:
        lines.append(
            f"| {e.ts.isoformat(timespec='seconds')} | {_cell(e.actor)} "
            f"| {_cell(e.action)} | {_cell(e.target)} | {_cell(e.result)} |"
        )
    lines.append("")

    return "\n".join(lines)
