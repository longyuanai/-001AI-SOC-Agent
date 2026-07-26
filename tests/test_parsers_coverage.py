"""Parser gaps that made real attacks invisible.

Only ``Failed``/``Accepted password`` were recognized, so key-based logins —
including successful ones — never reached the correlation rules. Syslog also
carries no year, so a file spanning New Year jumped backwards mid-stream.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ai_soc_agent.parsers import iter_file, parse_file, parse_line, parse_okta_record

HOST = "Jul 23 22:01:14 mail sshd[1234]: "


def test_failed_publickey_is_parsed() -> None:
    event = parse_line(
        HOST + "Failed publickey for root from 203.0.113.45 port 51234 ssh2: "
        "RSA SHA256:abcdef",
        year=2026,
    )

    assert event is not None
    assert event.result == "failure"
    assert event.actor == "203.0.113.45"
    assert event.target == "root"
    assert event.extra["auth_method"] == "publickey"


def test_accepted_publickey_is_parsed() -> None:
    event = parse_line(
        HOST + "Accepted publickey for deploy from 198.51.100.20 port 4242 ssh2: "
        "ED25519 SHA256:xyz",
        year=2026,
    )

    assert event is not None
    assert event.result == "success"
    assert event.target == "deploy"
    assert event.extra["auth_method"] == "publickey"


def test_keyboard_interactive_is_parsed() -> None:
    event = parse_line(
        HOST + "Failed keyboard-interactive/pam for admin from 203.0.113.9 port 22 ssh2",
        year=2026,
    )

    assert event is not None
    assert event.result == "failure"
    assert event.extra["auth_method"] == "keyboard-interactive/pam"


def test_invalid_user_line_is_parsed() -> None:
    event = parse_line(HOST + "Invalid user oracle from 203.0.113.45 port 51234", year=2026)

    assert event is not None
    assert event.result == "failure"
    assert event.target == "oracle"
    assert event.extra["reason"] == "invalid_user"


def test_preauth_connection_close_is_parsed() -> None:
    event = parse_line(
        HOST + "Connection closed by authenticating user root 203.0.113.45 "
        "port 51234 [preauth]",
        year=2026,
    )

    assert event is not None
    assert event.result == "failure"
    assert event.actor == "203.0.113.45"
    assert event.extra["reason"] == "preauth_close"


def test_unrelated_sshd_line_is_still_ignored() -> None:
    assert parse_line(HOST + "Server listening on 0.0.0.0 port 22.", year=2026) is None


def test_publickey_bruteforce_now_reaches_the_rules(tmp_path) -> None:
    """The whole point: key-auth failures must be correlatable."""
    from ai_soc_agent.correlator import detect_patterns

    path = tmp_path / "auth.log"
    path.write_text(
        "\n".join(
            f"Jul 23 22:01:{index:02d} mail sshd[{1000 + index}]: "
            f"Failed publickey for root from 203.0.113.45 port {51000 + index} ssh2: "
            "RSA SHA256:abc"
            for index in range(6)
        ),
        encoding="utf-8",
    )

    findings = detect_patterns(parse_file(str(path)))

    assert len(findings) == 1
    assert findings[0].host == "203.0.113.45"


def test_year_rolls_forward_across_new_year(tmp_path) -> None:
    path = tmp_path / "auth.log"
    path.write_text(
        "Dec 31 23:59:58 mail sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "Jan 01 00:00:02 mail sshd[2]: Failed password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    december, january = parse_file(str(path))

    assert january.ts > december.ts
    assert january.ts.year == december.ts.year + 1
    assert (january.ts - december.ts).total_seconds() == 4


def test_december_log_parsed_in_january_is_not_dated_in_the_future(tmp_path, monkeypatch) -> None:
    import ai_soc_agent.parsers as parsers

    class _FakeDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2027, 1, 2, tzinfo=tz)

    monkeypatch.setattr(parsers, "datetime", _FakeDatetime)
    path = tmp_path / "auth.log"
    path.write_text(
        "Dec 28 10:00:00 mail sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n",
        encoding="utf-8",
    )

    (event,) = parse_file(str(path))

    assert event.ts.year == 2026
    assert event.ts < datetime(2027, 1, 2, tzinfo=UTC)


def test_iter_file_streams_without_building_a_list(tmp_path) -> None:
    path = tmp_path / "auth.log"
    path.write_text(
        "\n".join(
            f"Jul 23 22:01:{index:02d} mail sshd[{index}]: "
            f"Failed password for root from 1.2.3.4 port 22 ssh2"
            for index in range(5)
        ),
        encoding="utf-8",
    )

    stream = iter_file(str(path))

    assert next(iter(stream)).target == "root"


def test_okta_sso_target_is_the_application() -> None:
    record = {
        "uuid": "evt-sso-1",
        "published": "2026-07-24T02:15:01.000Z",
        "eventType": "user.authentication.sso",
        "actor": {"alternateId": "alice@example.test"},
        "client": {"ipAddress": "203.0.113.45"},
        "outcome": {"result": "SUCCESS"},
        "target": [{"displayName": "Salesforce", "id": "0oa1sf"}],
    }

    event = parse_okta_record(record)

    assert event is not None
    assert event.target == "Salesforce"
    assert event.extra["user"] == "alice@example.test"


def test_okta_login_target_remains_the_user() -> None:
    record = {
        "uuid": "evt-login-1",
        "published": "2026-07-24T02:15:01.000Z",
        "eventType": "user.session.start",
        "actor": {"alternateId": "alice@example.test"},
        "client": {"ipAddress": "203.0.113.45"},
        "outcome": {"result": "SUCCESS"},
    }

    event = parse_okta_record(record)

    assert event is not None
    assert event.target == "alice@example.test"


def test_okta_json_array_file_still_parses(tmp_path) -> None:
    path = tmp_path / "okta.json"
    path.write_text(
        json.dumps(
            [
                {
                    "uuid": "evt-1",
                    "published": "2026-07-24T02:15:01.000Z",
                    "eventType": "user.session.start",
                    "actor": {"alternateId": "alice@example.test"},
                    "client": {"ipAddress": "203.0.113.45"},
                    "outcome": {"result": "SUCCESS"},
                }
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    assert len(parse_file(str(path), log_type="okta")) == 1


def test_unsupported_log_type_still_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported log type"):
        parse_file("ignored.log", log_type="syslog")
