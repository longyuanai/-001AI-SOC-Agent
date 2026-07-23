"""AI-SOC-Agent: log-analysis copilot for SOC analysts.

Stage-1 happy path: parse a flat log file of authentication events,
normalize each line into `NormalizedEvent`, push the top-N through the
shared LLM router, and print a structured Markdown report.
"""

from typing import Any

from ai_soc_agent.correlator import Alert, correlate, detect_credential_stuffing
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.parsers import parse_line

__version__ = "0.1.0"

__all__ = [
    "AlertAssessment",
    "Alert",
    "NormalizedEvent",
    "analyze_events",
    "correlate",
    "detect_credential_stuffing",
    "parse_line",
    "render_markdown",
    "__version__",
]


def __getattr__(name: str) -> Any:
    """Load LLM-dependent exports only when callers request them."""
    if name in {"AlertAssessment", "analyze_events"}:
        from ai_soc_agent.analyzer import AlertAssessment, analyze_events

        globals().update(
            {
                "AlertAssessment": AlertAssessment,
                "analyze_events": analyze_events,
            }
        )
        return globals()[name]
    if name == "render_markdown":
        from ai_soc_agent.reporter import render_markdown

        globals()["render_markdown"] = render_markdown
        return render_markdown
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
