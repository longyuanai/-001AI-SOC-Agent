"""Parsers for supported security log formats."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

from ai_soc_agent.normalizer import NormalizedEvent

# OpenSSH auth.log pattern (Debian / Ubuntu).
# Example: "Jul 23 22:01:14 host sshd[1234]: Failed password for invalid user
# root from 203.0.113.45 port 51234 ssh2"
_SSHD_RE = re.compile(
    r"^(?P<ts>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<msg>.+)$"
)

_FAILED_PASSWORD_RE = re.compile(
    r"Failed password for(?: invalid user)?\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

_ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted password for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

_WINDOWS_EVENT_RESULTS = {
    4624: "success",
    4625: "failure",
    4648: "unknown",
}

_WINDOWS_EVENT_ACTIONS = {
    4624: "windows_login",
    4625: "windows_login",
    4648: "windows_explicit_credentials",
}

_NGINX_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<request>\S+)(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"$'
)


def _parse_ts(token: str, year: int | None = None) -> datetime:
    """Parse 'Mon DD HH:MM:SS' into a datetime; year defaults to current."""
    if year is None:
        year = datetime.now().year
    return datetime.strptime(f"{year} {token}", "%Y %b %d %H:%M:%S")


def parse_line(line: str, *, year: int | None = None) -> NormalizedEvent | None:
    """Parse one log line. Returns None if the line doesn't match a known format."""
    line = line.rstrip("\n")
    m = _SSHD_RE.match(line)
    if m is None:
        return None

    msg = m.group("msg")
    ts = _parse_ts(m.group("ts"), year=year)
    host = m.group("host")

    if (fm := _FAILED_PASSWORD_RE.search(msg)):
        return NormalizedEvent(
            ts=ts,
            actor=fm.group("ip"),
            action="ssh_login",
            target=fm.group("user"),
            result="failure",
            source="sshd",
            raw=line,
            extra={"host": host, "port": int(fm.group("port"))},
        )

    if (am := _ACCEPTED_PASSWORD_RE.search(msg)):
        return NormalizedEvent(
            ts=ts,
            actor=am.group("ip"),
            action="ssh_login",
            target=am.group("user"),
            result="success",
            source="sshd",
            raw=line,
            extra={"host": host, "port": int(am.group("port"))},
        )

    return None


def _local_name(tag: str) -> str:
    """Return an XML tag name without its optional namespace."""
    return tag.rsplit("}", 1)[-1]


def _xml_child(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    return next((child for child in element if _local_name(child.tag) == name), None)


def _xml_text(element: ElementTree.Element | None, name: str) -> str:
    if element is None:
        return ""
    child = _xml_child(element, name)
    return (child.text or "").strip() if child is not None else ""


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_evtx_element(
    root: ElementTree.Element, *, raw: str | None = None
) -> NormalizedEvent | None:
    if _local_name(root.tag) != "Event":
        return None

    system = _xml_child(root, "System")
    event_id_text = _xml_text(system, "EventID")
    try:
        event_id = int(event_id_text)
    except ValueError:
        return None
    if event_id not in _WINDOWS_EVENT_RESULTS:
        return None

    time_created = _xml_child(system, "TimeCreated") if system is not None else None
    timestamp = time_created.attrib.get("SystemTime", "") if time_created is not None else ""
    ts = _parse_iso_datetime(timestamp)
    if ts is None:
        return None

    event_data = _xml_child(root, "EventData")
    data = {
        item.attrib["Name"]: (item.text or "").strip()
        for item in (event_data if event_data is not None else ())
        if _local_name(item.tag) == "Data" and item.attrib.get("Name")
    }
    computer = _xml_text(system, "Computer")
    source_ip = data.get("IpAddress", "")
    subject_user = data.get("SubjectUserName", "")
    target_user = data.get("TargetUserName", "")

    actor = source_ip if source_ip and source_ip != "-" else subject_user or "unknown"
    target = target_user or data.get("TargetServerName") or computer or "unknown"
    extra = {
        "event_id": event_id,
        "computer": computer,
        "subject_user": subject_user,
        "logon_type": data.get("LogonType", ""),
        "auth_package": data.get("AuthenticationPackageName", ""),
        "process_name": data.get("ProcessName", ""),
        "ip_port": data.get("IpPort", ""),
    }

    return NormalizedEvent(
        ts=ts,
        actor=actor,
        action=_WINDOWS_EVENT_ACTIONS[event_id],
        target=target,
        result=_WINDOWS_EVENT_RESULTS[event_id],
        source="windows",
        raw=raw if raw is not None else ElementTree.tostring(root, encoding="unicode"),
        extra={key: value for key, value in extra.items() if value not in ("", "-")},
    )


def parse_evtx_line(line: str) -> NormalizedEvent | None:
    """Parse one Windows Event XML record for Event IDs 4624, 4625, or 4648."""
    raw = line.strip()
    if not raw:
        return None
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return None
    return _parse_evtx_element(root, raw=raw)


def parse_nginx_line(line: str) -> NormalizedEvent | None:
    """Parse one Nginx combined access-log line."""
    raw = line.rstrip("\r\n")
    match = _NGINX_COMBINED_RE.match(raw)
    if match is None:
        return None

    try:
        ts = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    status = int(match.group("status"))
    if 100 <= status < 400:
        result = "success"
    elif 400 <= status < 600:
        result = "failure"
    else:
        result = "unknown"

    bytes_sent = match.group("bytes")
    extra = {
        "method": match.group("method"),
        "status": status,
        "bytes_sent": None if bytes_sent == "-" else int(bytes_sent),
        "protocol": match.group("protocol") or "",
        "remote_user": match.group("user"),
        "referer": match.group("referer"),
        "user_agent": match.group("user_agent"),
    }
    return NormalizedEvent(
        ts=ts,
        actor=match.group("ip"),
        action="http_request",
        target=match.group("request"),
        result=result,
        source="nginx",
        raw=raw,
        extra={
            key: value
            for key, value in extra.items()
            if value not in ("", "-")
        },
    )


def _parse_evtx_file(path: str) -> list[NormalizedEvent]:
    content = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if not content.strip():
        return []

    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return [
            event
            for line in content.splitlines()
            if line.strip() and (event := parse_evtx_line(line)) is not None
        ]

    elements = (
        [root]
        if _local_name(root.tag) == "Event"
        else [item for item in root.iter() if _local_name(item.tag) == "Event"]
    )
    return [
        event
        for element in elements
        if (event := _parse_evtx_element(element)) is not None
    ]


def parse_file(path: str, *, log_type: str = "sshd") -> list[NormalizedEvent]:
    """Parse a whole file using the selected log format."""
    if log_type == "evtx":
        return _parse_evtx_file(path)
    line_parsers = {
        "sshd": parse_line,
        "nginx": parse_nginx_line,
    }
    if log_type not in line_parsers:
        raise ValueError(f"Unsupported log type: {log_type}")

    events: list[NormalizedEvent] = []
    parser = line_parsers[log_type]
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            ev = parser(line)
            if ev is not None:
                events.append(ev)
    return events
