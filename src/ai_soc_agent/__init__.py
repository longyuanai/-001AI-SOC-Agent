"""AI-SOC-Agent: log-analysis copilot for SOC analysts.

Stage-1 happy path: parse a flat log file of authentication events,
normalize each line into `NormalizedEvent`, push the top-N through the
shared LLM router, and print a structured Markdown report.
"""

from ai_soc_agent.analyzer import analyze_events, AlertAssessment
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.parsers import parse_line
from ai_soc_agent.reporter import render_markdown

__version__ = "0.1.0"

__all__ = [
    "AlertAssessment",
    "NormalizedEvent",
    "analyze_events",
    "parse_line",
    "render_markdown",
    "__version__",
]