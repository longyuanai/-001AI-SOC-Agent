"""Tests for Okta System Log parsing."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ai_soc_agent.parsers import parse_file, parse_okta_record


def _record(
    *,
    event_type: str = "user.session.start",
    outcome: str = "SUCCESS",
    published: str = "2026-07-24T02:15:01.123Z",
) -> dict:
    return {
        "uuid": "evt-okta-001",
        "published": published,
        "eventType": event_type,
        "displayMessage": "User login to Okta",
        "actor": {
            "id": "00u1alice",
            "alternateId": "alice@example.test",
            "displayName": "Alice Example",
        },
        "client": {
            "ipAddress": "203.0.113.45",
            "userAgent": {"rawUserAgent": "Mozilla/5.0"},
        },
        "authenticationContext": {
            "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
            "credentialType": "PASSWORD",
        },
        "outcome": {"result": outcome, "reason": None},
    }


def test_parse_okta_successful_login():
    event = parse_okta_record(_record())

    assert event is not None
    assert event.ts == datetime(2026, 7, 24, 2, 15, 1, 123000, tzinfo=UTC)
    assert event.actor == "203.0.113.45"
    assert event.action == "okta_login"
    assert event.target == "alice@example.test"
    assert event.result == "success"
    assert event.source == "okta"
    assert event.extra["event_id"] == "evt-okta-001"
    assert event.extra["credential_type"] == "PASSWORD"


def test_parse_okta_failed_login():
    record = _record(outcome="FAILURE")
    record["outcome"]["reason"] = "INVALID_CREDENTIALS"

    event = parse_okta_record(record)

    assert event is not None
    assert event.result == "failure"
    assert event.extra["outcome_reason"] == "INVALID_CREDENTIALS"
    assert event.extra["user_agent"] == "Mozilla/5.0"


def test_parse_okta_mfa_and_sso_actions():
    mfa = parse_okta_record(_record(event_type="user.authentication.auth_via_mfa"))
    sso = parse_okta_record(_record(event_type="user.authentication.sso"))

    assert mfa is not None
    assert mfa.action == "okta_mfa"
    assert sso is not None
    assert sso.action == "okta_sso"


def test_parse_okta_falls_back_to_user_without_client_ip():
    record = _record(outcome="SKIPPED")
    record["client"] = {}

    event = parse_okta_record(record)

    assert event is not None
    assert event.actor == "alice@example.test"
    assert event.result == "unknown"


def test_parse_okta_rejects_non_login_or_invalid_timestamp():
    assert parse_okta_record(_record(event_type="group.user_membership.add")) is None
    assert parse_okta_record(_record(published="not-a-timestamp")) is None


def test_parse_okta_json_array_file(tmp_path):
    path = tmp_path / "okta.json"
    path.write_text(
        json.dumps([_record(), _record(event_type="group.user_membership.add")]),
        encoding="utf-8",
    )

    events = parse_file(str(path), log_type="okta")

    assert len(events) == 1
    assert events[0].source == "okta"


def test_parse_okta_jsonl_skips_malformed_records(tmp_path):
    path = tmp_path / "okta.jsonl"
    path.write_text(
        json.dumps(_record(outcome="FAILURE"))
        + "\nnot-json\n"
        + json.dumps(_record(event_type="user.authentication.sso"))
        + "\n",
        encoding="utf-8",
    )

    events = parse_file(str(path), log_type="okta")

    assert [event.result for event in events] == ["failure", "success"]
    assert events[1].action == "okta_sso"
