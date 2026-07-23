"""Tests for Nginx combined access-log parsing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ai_soc_agent.parsers import parse_file, parse_nginx_line


def test_parse_nginx_success():
    event = parse_nginx_line(
        '203.0.113.45 - - [24/Jul/2026:09:15:01 +0800] '
        '"GET /login HTTP/1.1" 200 1842 "https://example.test/" "Mozilla/5.0"'
    )

    assert event is not None
    assert event.ts == datetime(
        2026, 7, 24, 9, 15, 1, tzinfo=timezone(timedelta(hours=8))
    )
    assert event.actor == "203.0.113.45"
    assert event.action == "http_request"
    assert event.target == "/login"
    assert event.result == "success"
    assert event.source == "nginx"
    assert event.extra["method"] == "GET"
    assert event.extra["status"] == 200
    assert event.extra["bytes_sent"] == 1842


def test_parse_nginx_failure_preserves_request_metadata():
    event = parse_nginx_line(
        '198.51.100.20 - alice [24/Jul/2026:09:16:10 +0800] '
        '"POST /api/session HTTP/2.0" 401 97 "-" "python-requests/2.32.0"'
    )

    assert event is not None
    assert event.target == "/api/session"
    assert event.result == "failure"
    assert event.extra["method"] == "POST"
    assert event.extra["protocol"] == "HTTP/2.0"
    assert event.extra["remote_user"] == "alice"
    assert event.extra["user_agent"] == "python-requests/2.32.0"
    assert "referer" not in event.extra


def test_parse_nginx_dash_bytes_and_ipv6():
    event = parse_nginx_line(
        '2001:db8::5 - - [24/Jul/2026:09:17:00 +0000] '
        '"HEAD /health HTTP/1.1" 304 - "-" "monitor/1.0"'
    )

    assert event is not None
    assert event.actor == "2001:db8::5"
    assert event.result == "success"
    assert event.extra["bytes_sent"] is None


def test_parse_nginx_rejects_malformed_lines():
    assert parse_nginx_line("not an access log") is None
    assert (
        parse_nginx_line(
            '203.0.113.45 - - [bad timestamp] "GET / HTTP/1.1" 200 1 "-" "agent"'
        )
        is None
    )


def test_parse_nginx_file_skips_unrecognized_lines(tmp_path):
    path = tmp_path / "access.log"
    path.write_text(
        '203.0.113.45 - - [24/Jul/2026:09:15:01 +0800] '
        '"GET / HTTP/1.1" 200 10 "-" "agent"\n'
        "malformed\n"
        '203.0.113.46 - - [24/Jul/2026:09:15:02 +0800] '
        '"GET /admin HTTP/1.1" 403 20 "-" "agent"\n',
        encoding="utf-8",
    )

    events = parse_file(str(path), log_type="nginx")

    assert [event.result for event in events] == ["success", "failure"]
