"""Tests for the CLI."""

from __future__ import annotations

import io
import json
import sys

import click
import pytest
from click.testing import CliRunner

from ai_soc_agent.cli import _payload_events, cli, main


def test_cli_help():
    runner = CliRunner()
    res = runner.invoke(cli, ["--help"])
    assert res.exit_code == 0
    assert "log analysis copilot" in res.output.lower()


def test_cli_analyze_missing_input(tmp_path):
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", "--input", str(tmp_path / "missing.log")])
    # Click returns 2 when required option / path is bad.
    assert res.exit_code != 0


def test_cli_analyze_unrecognized_log(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("nothing recognizable here\n", encoding="utf-8")
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", "--input", str(empty)])
    # Should exit cleanly (0) after warning "no events".
    assert res.exit_code == 0
    assert "No recognizable" in res.output


def test_cli_analyze_help_lists_evtx_log_type():
    runner = CliRunner()
    res = runner.invoke(cli, ["analyze", "--help"])

    assert res.exit_code == 0
    assert "--log-type" in res.output
    assert "sshd" in res.output
    assert "evtx" in res.output
    assert "nginx" in res.output
    assert "okta" in res.output


def test_cli_scan_help_lists_log_type():
    res = CliRunner().invoke(cli, ["scan", "--help"])

    assert res.exit_code == 0
    assert "--log-type" in res.output


_NGINX_LINE = (
    '203.0.113.45 - - [24/Jul/2026:09:15:03 +0800] '
    '"POST /login HTTP/1.1" 401 97 "-" "curl"'
)


def test_scan_log_type_selects_the_parser():
    """`scan` had no --log-type, so non-sshd input silently parsed to nothing."""
    payload = {"source": "sshd", "events": [_NGINX_LINE]}

    as_sshd, _ = _payload_events(payload)
    as_nginx, _ = _payload_events(payload, log_type="nginx")

    assert as_sshd == []
    assert len(as_nginx) == 1
    assert as_nginx[0].source == "nginx"


def test_scan_log_type_overrides_payload_source():
    payload = {"source": "okta", "events": [_NGINX_LINE]}

    events, _ = _payload_events(payload, log_type="nginx")

    assert len(events) == 1


def test_unknown_log_type_is_rejected():
    with pytest.raises(click.ClickException, match="unsupported source"):
        _payload_events({"source": "syslog", "events": []})


def test_scan_log_file_honours_log_type(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(_NGINX_LINE + "\n", encoding="utf-8")

    as_sshd, _ = _payload_events({}, log_file=str(path))
    as_nginx, _ = _payload_events({}, log_file=str(path), log_type="nginx")

    assert as_sshd == []
    assert len(as_nginx) == 1


def _run_main(monkeypatch, argv: list[str]) -> int:
    monkeypatch.setattr(sys, "argv", ["ai-soc", *argv])
    try:
        main()
    except SystemExit as exit_code:
        return int(exit_code.code or 0)
    return 0


def test_main_routes_bare_options_to_scan(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO('{"source":"sshd","events":[]}'))

    assert _run_main(monkeypatch, ["--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"findings": []}


def test_main_keeps_explicit_subcommands(monkeypatch, capsys):
    assert _run_main(monkeypatch, ["analyze", "--help"]) == 0
    assert "incident report" in capsys.readouterr().out.lower()


def test_main_leaves_group_options_alone(monkeypatch, capsys):
    assert _run_main(monkeypatch, ["--version"]) == 0
    assert "0.1.0" in capsys.readouterr().out


def test_main_routes_a_newly_added_scan_option(monkeypatch, capsys):
    """The old argv sniffing only knew --json/--input/--log-file by name."""
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    assert _run_main(monkeypatch, ["--log-type", "nginx", "--json"]) != 0
    assert "missing JSON payload" in capsys.readouterr().err
