"""CLI entry point for log parsing, analysis, and reporting."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from ai_soc_agent import __version__
from ai_soc_agent.analyzer import AssessmentError, analyze_events
from ai_soc_agent.correlator import detect_patterns
from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.parsers import (
    parse_evtx_line,
    parse_file,
    parse_line,
    parse_nginx_line,
    parse_okta_record,
)
from ai_soc_agent.patterns import RULE_MANIFESTS, validate_builtin_manifests
from ai_soc_agent.reporter import render_markdown

logger = logging.getLogger(__name__)
console = Console()
_LOG_TYPES = ("sshd", "evtx", "nginx", "okta")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise click.ClickException("normalized event 'ts' must be an ISO-8601 string")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise click.ClickException(f"invalid normalized event timestamp: {value}") from exc


def _normalized_event(item: dict[str, Any], source: str) -> NormalizedEvent | None:
    required = {"ts", "actor", "action", "target", "result"}
    if not required.issubset(item):
        return None
    extra = item.get("extra", {})
    if not isinstance(extra, dict):
        raise click.ClickException("normalized event 'extra' must be an object")
    # Fall back to the submitted payload so evidence stays traceable to what
    # the caller actually sent. Without it the adapter had to staple the whole
    # input batch onto every finding.
    raw = item.get("raw")
    return NormalizedEvent(
        ts=_parse_timestamp(item["ts"]),
        actor=str(item["actor"]),
        action=str(item["action"]),
        target=str(item["target"]),
        result=str(item["result"]),
        source=str(item.get("source", source)),
        raw=str(raw) if raw not in (None, "") else str(item),
        extra=extra,
    )


def _payload_events(
    payload: dict[str, Any], *, log_file: str | None = None
) -> tuple[list[NormalizedEvent], int]:
    source = str(payload.get("source", "sshd")).casefold()
    if source not in _LOG_TYPES:
        raise click.ClickException(
            f"unsupported source {source!r}; expected one of {', '.join(_LOG_TYPES)}"
        )

    requested_file = log_file or payload.get("log_file") or payload.get("path")
    if requested_file is not None:
        if not isinstance(requested_file, str):
            raise click.ClickException("payload log file path must be a string")
        path = Path(requested_file)
        if not path.is_file():
            raise click.ClickException(f"log file does not exist: {requested_file}")
        parsed = parse_file(str(path), log_type=source)
        threshold = _brute_force_threshold(payload)
        return parsed, threshold

    raw_events = payload.get("events", [])
    if not isinstance(raw_events, list):
        raise click.ClickException("payload 'events' must be a list")

    parsed: list[NormalizedEvent] = []
    for item in raw_events:
        event: NormalizedEvent | None
        if isinstance(item, dict):
            event = _normalized_event(item, source)
            if event is None and source == "okta":
                event = parse_okta_record(item)
            elif event is None:
                raw = item.get("raw")
                event = _parse_raw_event(raw, source) if isinstance(raw, str) else None
        elif isinstance(item, str):
            event = _parse_raw_event(item, source)
        else:
            event = None
        if event is not None:
            parsed.append(event)

    if (dropped := len(raw_events) - len(parsed)) > 0:
        logger.warning(
            "%d of %d submitted %s events did not parse and were skipped",
            dropped,
            len(raw_events),
            source,
        )

    return parsed, _brute_force_threshold(payload)


def _brute_force_threshold(payload: dict[str, Any]) -> int:
    threshold = payload.get("brute_force_threshold", 5)
    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold <= 0:
        raise click.ClickException("'brute_force_threshold' must be a positive integer")
    return threshold


def _parse_raw_event(raw: str, source: str) -> NormalizedEvent | None:
    if source == "sshd":
        return parse_line(raw)
    if source == "evtx":
        return parse_evtx_line(raw)
    if source == "nginx":
        return parse_nginx_line(raw)
    if source == "okta":
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parse_okta_record(record) if isinstance(record, dict) else None
    return None


def scan_payload(
    payload: dict[str, Any], *, log_file: str | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Convert an IntegrationGateway payload into its Finding envelope."""
    events, threshold = _payload_events(payload, log_file=log_file)
    findings = detect_patterns(
        events,
        facts={"brute_force_threshold": threshold},
    )
    serialized = []
    for finding in findings:
        item = finding.to_dict()
        item.pop("source")
        serialized.append(item)
    return {"findings": serialized}


class _DefaultCommandGroup(click.Group):
    """Route bare options to ``scan`` so ``... --json`` keeps working.

    Replaces a hand-rolled argv sniffer that inserted "scan" whenever the first
    argument started with "-" and any argument matched a hardcoded option list;
    it broke as soon as scan grew an option.
    """

    default_command = "scan"

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and args[0].startswith("-") and args[0] not in ("--help", "--version"):
            args = [self.default_command, *args]
        return super().parse_args(ctx, args)


@click.group(cls=_DefaultCommandGroup)
@click.version_option(__version__)
def cli() -> None:
    """AI-SOC-Agent: log analysis copilot."""


@cli.group("rules")
def rules_group() -> None:
    """Inspect and validate built-in detection rule manifests."""


@rules_group.command("list")
@click.option("--json", "json_output", is_flag=True, help="Emit a JSON rule envelope.")
def list_rules(json_output: bool) -> None:
    """List the built-in Sigma-compatible rule manifests."""
    manifests = [manifest.to_dict() for manifest in RULE_MANIFESTS]
    if json_output:
        click.echo(
            json.dumps(
                {"rules": manifests},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return

    for manifest in manifests:
        click.echo(
            f"{manifest['id']}\t{manifest['severity']}\t{manifest['title']}"
        )


@rules_group.command("validate")
def validate_rules() -> None:
    """Validate manifests against executable rules and entry points."""
    errors = validate_builtin_manifests()
    if errors:
        raise click.ClickException("\n".join(errors))
    click.echo(f"{len(RULE_MANIFESTS)} rule manifest(s) valid")


@cli.command()
@click.option(
    "--input",
    "input_json",
    help="IntegrationGateway JSON payload; reads stdin when omitted.",
)
@click.option(
    "--log-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Read events from a real log file; source defaults to sshd.",
)
@click.option("--json", "json_output", is_flag=True, help="Emit a Finding JSON envelope.")
def scan(input_json: str | None, log_file: str | None, json_output: bool) -> None:
    """Scan normalized or raw events without calling an LLM."""
    raw_payload = input_json
    if raw_payload is None and log_file is None:
        raw_payload = sys.stdin.read()
    if raw_payload is None:
        payload: Any = {}
    elif not raw_payload.strip():
        raise click.ClickException("missing JSON payload: use --input, --log-file, or stdin")
    else:
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise click.ClickException(
                f"invalid JSON payload at line {exc.lineno}, column {exc.colno}"
            ) from exc
    if not isinstance(payload, dict):
        raise click.ClickException("JSON payload must be an object")

    envelope = scan_payload(payload, log_file=log_file)
    if json_output:
        click.echo(json.dumps(envelope, ensure_ascii=False, separators=(",", ":")))
        return

    click.echo(f"{len(envelope['findings'])} finding(s)")
    for finding in envelope["findings"]:
        click.echo(f"- [{finding['severity']}] {finding['title']}")


async def _serve_syslog(
    *,
    host: str,
    port: int,
    queue_size: int,
    json_output: bool,
) -> None:
    """Run the bounded UDP receiver until the process is interrupted."""
    from ai_soc_agent.config import DetectionConfig
    from ai_soc_agent.dedup import FindingDeduplicator
    from ai_soc_agent.ingest import SyslogUDPReceiver
    from ai_soc_agent.state import WindowStateStore

    settings = DetectionConfig.for_stream()
    state = WindowStateStore()
    deduplicator = FindingDeduplicator()

    def handle(event: NormalizedEvent) -> None:
        state.append([event])
        findings = detect_patterns(
            state.snapshot(limit=5_000),
            facts={
                **settings.as_facts(),
                "credential_stuffing_mode": "cross_source",
            },
        )
        emitted = [finding for finding in findings if deduplicator.accept(finding).accepted]
        if not emitted:
            return
        serialized = []
        for finding in emitted:
            item = finding.to_dict()
            item.pop("source")
            serialized.append(item)
        if json_output:
            click.echo(
                json.dumps(
                    {"findings": serialized},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
            return
        for item in serialized:
            click.echo(f"[{item['severity']}] {item['title']}")

    receiver = SyslogUDPReceiver(handle, queue_size=queue_size)
    address = await receiver.start(host=host, port=port)
    click.echo(
        f"Listening for RFC 3164 sshd syslog on udp://{address[0]}:{address[1]}",
        err=True,
    )
    try:
        await asyncio.Future()
    finally:
        await receiver.close()
        click.echo(
            json.dumps(receiver.health(), ensure_ascii=False, default=str),
            err=True,
        )


@cli.command("syslog")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", type=click.IntRange(0, 65_535), default=1514, show_default=True)
@click.option(
    "--queue-size",
    type=click.IntRange(min=1),
    default=1_024,
    show_default=True,
    help="Maximum datagrams waiting for parsing.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit one Finding envelope per detected incident.",
)
def syslog_command(host: str, port: int, queue_size: int, json_output: bool) -> None:
    """Receive RFC 3164 sshd events over bounded UDP (default port 1514)."""
    try:
        asyncio.run(
            _serve_syslog(
                host=host,
                port=port,
                queue_size=queue_size,
                json_output=json_output,
            )
        )
    except KeyboardInterrupt:
        click.echo("Syslog receiver stopped.", err=True)
    except OSError as exc:
        raise click.ClickException(f"could not bind UDP syslog listener: {exc}") from exc


@cli.command()
@click.option("--input", "-i", "input_path", required=True, type=click.Path(exists=True))
@click.option("--output", "-o", "output_path", default="-", type=click.Path())
@click.option(
    "--log-type",
    type=click.Choice(_LOG_TYPES, case_sensitive=False),
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
    try:
        with LLMRouter.from_env() as router:
            assessment = analyze_events(events, router)
    except (AssessmentError, ValueError) as exc:
        raise click.ClickException(f"LLM triage failed: {exc}") from exc

    report = render_markdown(events, assessment, source_path=input_path)
    if output_path == "-":
        sys.stdout.write(report)
    else:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"[green]Wrote[/green] {output_path}")


def main() -> None:
    cli.main(args=sys.argv[1:], prog_name="python -m ai_soc_agent.cli")


if __name__ == "__main__":
    main()
