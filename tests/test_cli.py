"""Tests for the CLI."""

from __future__ import annotations

from click.testing import CliRunner

from ai_soc_agent.cli import cli


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


def test_cli_syslog_help_uses_unprivileged_defaults():
    runner = CliRunner()
    res = runner.invoke(cli, ["syslog", "--help"])

    assert res.exit_code == 0
    assert "1514" in res.output
    assert "127.0.0.1" in res.output
    assert "--queue-size" in res.output


def test_cli_syslog_rejects_non_positive_queue_size():
    runner = CliRunner()
    res = runner.invoke(cli, ["syslog", "--queue-size", "0"])

    assert res.exit_code != 0
    assert "Invalid value for '--queue-size'" in res.output


def test_cli_syslog_help_uses_unprivileged_defaults():
    runner = CliRunner()
    res = runner.invoke(cli, ["syslog", "--help"])

    assert res.exit_code == 0
    assert "1514" in res.output
    assert "127.0.0.1" in res.output
    assert "--queue-size" in res.output


def test_cli_syslog_rejects_non_positive_queue_size():
    runner = CliRunner()
    res = runner.invoke(cli, ["syslog", "--queue-size", "0"])

    assert res.exit_code != 0
    assert "Invalid value for '--queue-size'" in res.output
