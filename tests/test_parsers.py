"""Tests for the SSH parser. Pure logic — no LLM calls."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from ai_soc_agent.parsers import parse_file, parse_line


@pytest.fixture
def sample_log(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Jul 23 22:01:14 host sshd[1234]: Failed password for invalid user root"
        " from 1.2.3.4 port 22 ssh2\n"
        "Jul 23 22:01:16 host sshd[1234]: Accepted password for alice"
        " from 1.2.3.4 port 22 ssh2\n"
        "Jul 23 22:01:18 host sshd[999]: Some other message that we ignore\n",
        encoding="utf-8",
    )
    return p


def test_parse_failed_password():
    line = (
        "Jul 23 22:01:14 host sshd[1234]: Failed password for invalid user root"
        " from 1.2.3.4 port 22 ssh2"
    )
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
    ev = parse_line(
        "Jul 23 22:01:18 host sshd[999]:"
        " Did not receive identification string from 1.2.3.4"
    )
    assert ev is None


def test_parse_file_skips_unrecognized(sample_log):
    events = parse_file(str(sample_log))
    assert len(events) == 2
    assert [e.result for e in events] == ["failure", "success"]
    assert {e.actor for e in events} == {"1.2.3.4"}

def test_parse_failed_publickey_is_recognized():
    """Key-only servers log 'Failed publickey', which the old pattern dropped."""
    ev = parse_line(
        "Jul 23 22:01:14 host sshd[1234]: Failed publickey for root"
        " from 1.2.3.4 port 22 ssh2",
        year=2026,
    )

    assert ev is not None
    assert ev.result == "failure"
    assert ev.target == "root"
    assert ev.extra["auth_method"] == "publickey"


def test_parse_accepted_publickey_is_recognized():
    ev = parse_line(
        "Jul 23 22:01:16 host sshd[1234]: Accepted publickey for alice"
        " from 5.6.7.8 port 54321 ssh2: RSA SHA256:abc",
        year=2026,
    )

    assert ev is not None
    assert ev.result == "success"
    assert ev.extra["auth_method"] == "publickey"


def test_parse_records_the_password_auth_method():
    ev = parse_line(
        "Jul 23 22:01:14 host sshd[1234]: Failed password for invalid user root"
        " from 1.2.3.4 port 22 ssh2",
        year=2026,
    )

    assert ev is not None
    assert ev.extra["auth_method"] == "password"


def test_syslog_year_is_inferred_as_last_year_across_new_year():
    """A December line read in January is last year's, not eleven months ahead."""
    ev = parse_line(
        "Dec 31 23:59:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22",
        now=datetime(2027, 1, 2, 10, 0, 0),
    )

    assert ev is not None
    assert ev.ts == datetime(2026, 12, 31, 23, 59, 0)


def test_syslog_year_uses_the_current_year_for_past_dates():
    ev = parse_line(
        "Jul 23 22:01:14 host sshd[1]: Failed password for root from 1.2.3.4 port 22",
        now=datetime(2026, 7, 25, 10, 0, 0),
    )

    assert ev is not None
    assert ev.ts == datetime(2026, 7, 23, 22, 1, 14)


def test_syslog_year_tolerates_small_clock_skew():
    """An event a few minutes ahead of the clock is not pushed back a year."""
    ev = parse_line(
        "Jul 25 10:05:00 host sshd[1]: Failed password for root from 1.2.3.4 port 22",
        now=datetime(2026, 7, 25, 10, 0, 0),
    )

    assert ev is not None
    assert ev.ts.year == 2026


def test_new_year_burst_stays_inside_one_correlation_window():
    """The rollover bug split a burst by a full year, so no window ever fired."""
    now = datetime(2027, 1, 1, 0, 5, 0)
    stamps = [f"Dec 31 23:59:{50 + index}" for index in range(5)]
    stamps += [f"Jan  1 00:00:0{index}" for index in range(5)]
    events = [
        parse_line(
            f"{stamp} host sshd[1]: Failed password for root from 1.2.3.4 port 22",
            now=now,
        )
        for stamp in stamps
    ]

    assert all(event is not None for event in events)
    span = max(e.ts for e in events) - min(e.ts for e in events)
    assert span < timedelta(minutes=1)
