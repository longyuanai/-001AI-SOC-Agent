"""Tests for Windows Event XML parsing."""

from __future__ import annotations

from datetime import datetime, timezone

from ai_soc_agent.parsers import parse_evtx_line, parse_file


def _event_xml(event_id: int, event_data: str, *, timestamp: str = "2026-07-24T01:02:03Z") -> str:
    return f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>{event_id}</EventID>
        <TimeCreated SystemTime="{timestamp}"/>
        <Computer>dc01.example.test</Computer>
      </System>
      <EventData>{event_data}</EventData>
    </Event>
    """


def test_parse_evtx_4625_failure():
    event = parse_evtx_line(
        _event_xml(
            4625,
            """
            <Data Name="SubjectUserName">DC01$</Data>
            <Data Name="TargetUserName">administrator</Data>
            <Data Name="LogonType">3</Data>
            <Data Name="IpAddress">203.0.113.45</Data>
            <Data Name="IpPort">51234</Data>
            """,
        )
    )

    assert event is not None
    assert event.ts == datetime(2026, 7, 24, 1, 2, 3, tzinfo=timezone.utc)
    assert event.actor == "203.0.113.45"
    assert event.target == "administrator"
    assert event.action == "windows_login"
    assert event.result == "failure"
    assert event.source == "windows"
    assert event.extra["event_id"] == 4625
    assert event.extra["logon_type"] == "3"


def test_parse_evtx_4624_success():
    event = parse_evtx_line(
        _event_xml(
            4624,
            """
            <Data Name="TargetUserName">alice</Data>
            <Data Name="IpAddress">198.51.100.20</Data>
            """,
        )
    )

    assert event is not None
    assert event.actor == "198.51.100.20"
    assert event.target == "alice"
    assert event.result == "success"


def test_parse_evtx_4648_uses_subject_when_ip_missing():
    event = parse_evtx_line(
        _event_xml(
            4648,
            """
            <Data Name="SubjectUserName">alice</Data>
            <Data Name="TargetUserName">svc-backup</Data>
            <Data Name="ProcessName">C:\\Windows\\System32\\runas.exe</Data>
            <Data Name="IpAddress">-</Data>
            """,
        )
    )

    assert event is not None
    assert event.actor == "alice"
    assert event.target == "svc-backup"
    assert event.action == "windows_explicit_credentials"
    assert event.result == "unknown"
    assert event.extra["process_name"].endswith("runas.exe")


def test_parse_evtx_rejects_unsupported_or_malformed_records():
    assert parse_evtx_line(_event_xml(4634, "")) is None
    assert parse_evtx_line("<Event>") is None
    assert parse_evtx_line("") is None


def test_parse_evtx_file_reads_namespaced_event_container(tmp_path):
    path = tmp_path / "events.xml"
    ip_data = '<Data Name="IpAddress">1.2.3.4</Data>'
    path.write_text(
        f"<Events>{_event_xml(4625, ip_data)}"
        f"{_event_xml(9999, '')}</Events>",
        encoding="utf-8",
    )

    events = parse_file(str(path), log_type="evtx")

    assert len(events) == 1
    assert events[0].extra["event_id"] == 4625
