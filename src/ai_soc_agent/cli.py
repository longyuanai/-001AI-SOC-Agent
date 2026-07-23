"""CLI entry point for log parsing, analysis, and reporting."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from ai_soc_agent import __version__
from ai_soc_agent.analyzer import analyze_events
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.parsers import parse_file
from ai_soc_agent.reporter import render_markdown

console = Console()


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """AI-SOC-Agent: log analysis copilot."""


@cli.command()
@click.option("--input", "-i", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", "-o", "output_path", default="-", type=click.Path())
@click.option(
    "--log-type",
    type=click.Choice(["sshd", "evtx", "nginx"], case_sensitive=False),
    default="sshd",
    show_default=True,
    help="Input log format.",
)
@click.option(
    "--provider",
    "-p",
    default="local",
    show_default=True,
    help="Provider name from LLM_PROVIDERS env var.",
)
def analyze(input_path: str, output_path: str, log_type: str, provider: str) -> None:
    """Parse a log file and produce an incident report."""
    import os

    from shared_llm_core.router import LLMRouter

    os.environ.setdefault("LLM_PROVIDERS", provider)

    console.print(f"[bold]Parsing[/bold] {input_path} ...")
    events: list[NormalizedEvent] = parse_file(input_path, log_type=log_type)
    console.print(f"  [green]{len(events)}[/green] events parsed")

    if not events:
        console.print("[yellow]No recognizable events; nothing to do.[/yellow]")
        return

    console.print("[bold]Analyzing[/bold] via shared-llm-core ...")
    with LLMRouter.from_env() as router:
        assessment = analyze_events(events, router)

    report = render_markdown(events, assessment, source_path=input_path)
    if output_path == "-":
        sys.stdout.write(report)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"[green]Wrote[/green] {output_path}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
