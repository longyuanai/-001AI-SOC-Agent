"""Tests for the SSH parser. Pure logic — no LLM calls."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_soc_agent.parsers import parse_file, parse_line


@pytest.fixture
def sample_log(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Jul 23 22:01:14 host sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2\n"
        "Jul 23 22:01:16 host sshd[1234]: Accepted password for alice from 1.2.3.4 port 22 ssh2\n"
        "Jul 23 22:01:18 host sshd[999]: Some other message that we ignore\n",
        encoding="utf-8",
    )
    return p


def test_parse_failed_password():
    line = "Jul 23 22:01:14 host sshd[1234]: Failed password for invalid user root from 1.2.3.4 port 22 ssh2"
    ev = parse_line(line, year=2026)
    assert ev is not None
    assert ev.actor == "1.2.3.4"
    assert ev.target == "root"
    assert ev.result == "failure"
    assert ev.action == "ssh_login"
    assert ev.source == "sshd"
    assert ev.extra["port"] == 22
    assert ev.ts == datetime(2026, 7, 23, 22, 1, 14)


def test_parse_accepted_password():
    line = "Jul 23 22:01:16 host sshd[1234]: Accepted password for alice from 5.6.7.8 port 54321"
    ev = parse_line(line, year=2026)
    assert ev is not None
    assert ev.actor == "5.6.7.8"
    assert ev.target == "alice"
    assert ev.result == "success"
    assert ev.extra["port"] == 54321


def test_parse_non_sshd_line_returns_none():
    ev = parse_line("Jul 23 22:01:18 host CRON[999]: pam_unix(cron:session): session opened")
    assert ev is None


def test_parse_sshd_other_message_returns_none():
    ev = parse_line("Jul 23 22:01:18 host sshd[999]: Did not receive identification string from 1.2.3.4")
    assert ev is None


def test_parse_file_skips_unrecognized(sample_log):
    events = parse_file(str(sample_log))
    assert len(events) == 2
    assert [e.result for e in events] == ["failure", "success"]
    assert {e.actor for e in events} == {"1.2.3.4"}