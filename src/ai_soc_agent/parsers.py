"""Parsers for supported security log formats."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
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

# Any auth method, not just "password": a key-only server logs "Failed publickey
# for root from ...", which the password-only patterns dropped on the floor, so
# key-probing bursts were invisible to T1110.
_FAILED_AUTH_RE = re.compile(
    r"Failed (?P<method>\S+) for(?: invalid user)?\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

_ACCEPTED_AUTH_RE = re.compile(
    r"Accepted (?P<method>\S+) for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
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

# Path segments that mean "this request is an authentication attempt". Needed
# because every nginx event used to be action="http_request", which contains no
# "login" token, so T1110 could never fire on web brute force.
_LOGIN_SEGMENTS = frozenset(
    {
        "auth",
        "authenticate",
        "login",
        "log-in",
        "logon",
        "oauth",
        "session",
        "sessions",
        "signin",
        "sign-in",
        "sso",
        "token",
    }
)

#: Only these verbs submit credentials; GET /login is just loading the form.
_AUTH_METHODS = frozenset({"POST", "PUT", "PATCH"})

#: Static assets never authenticate, whatever they are named (login.css).
_STATIC_SUFFIXES = frozenset(
    {"css", "js", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf"}
)

_OKTA_EVENT_ACTIONS = {
    "user.session.start": "okta_login",
    "user.authentication.auth_via_mfa": "okta_mfa",
    "user.authentication.sso": "okta_sso",
}


def _parse_ts(
    token: str, year: int | None = None, *, now: datetime | None = None
) -> datetime:
    """Parse 'Mon DD HH:MM:SS' into a datetime, inferring the omitted year.

    Syslog carries no year. Blindly stamping on the current one puts a December
    log read in January eleven months in the *future*, which silently splits
    every correlation window that straddles New Year. Dates more than a day
    ahead of ``now`` are therefore read as last year's.
    """
    if year is not None:
        return datetime.strptime(f"{year} {token}", "%Y %b %d %H:%M:%S")

    reference = now or datetime.now()
    parsed = datetime.strptime(f"{reference.year} {token}", "%Y %b %d %H:%M:%S")
    if parsed - reference <= timedelta(days=1):
        return parsed
    try:
        return parsed.replace(year=reference.year - 1)
    except ValueError:
        # Feb 29 with a non-leap previous year: the log cannot be from last
        # year, so the current-year reading was right after all.
        return parsed


def parse_line(
    line: str, *, year: int | None = None, now: datetime | None = None
) -> NormalizedEvent | None:
    """Parse one log line. Returns None if the line doesn't match a known format."""
    line = line.rstrip("\n")
    m = _SSHD_RE.match(line)
    if m is None:
        return None

    msg = m.group("msg")
    ts = _parse_ts(m.group("ts"), year=year, now=now)
    host = m.group("host")

    for pattern, result in ((_FAILED_AUTH_RE, "failure"), (_ACCEPTED_AUTH_RE, "success")):
        if (match := pattern.search(msg)) is None:
            continue
        return NormalizedEvent(
            ts=ts,
            actor=match.group("ip"),
            action="ssh_login",
            target=match.group("user"),
            result=result,
            source="sshd",
            raw=line,
            extra={
                "host": host,
                "port": int(match.group("port")),
                "auth_method": match.group("method").casefold(),
            },
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


def is_login_endpoint(request: str) -> bool:
    """Return whether a request target looks like an authentication endpoint."""
    path = request.split("?", 1)[0].split("#", 1)[0]
    segments = [segment.casefold() for segment in path.split("/") if segment]
    if not segments:
        return False

    last = segments[-1]
    stem, _, suffix = last.rpartition(".")
    if stem and suffix in _STATIC_SUFFIXES:
        return False

    if any(segment in _LOGIN_SEGMENTS for segment in segments):
        return True
    # wp-login.php, user_login.jsp, doSignin.do, ...
    return any(token in (stem or last) for token in ("login", "signin", "logon"))


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

    method = match.group("method")
    request = match.group("request")
    is_login = method.upper() in _AUTH_METHODS and is_login_endpoint(request)

    bytes_sent = match.group("bytes")
    extra = {
        "method": method,
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
        action="web_login" if is_login else "http_request",
        target=request,
        result=result,
        source="nginx",
        raw=raw,
        extra={key: value for key, value in extra.items() if value not in ("", "-")},
    )


def parse_okta_record(record: dict) -> NormalizedEvent | None:
    """Parse one Okta System Log login/authentication record."""
    event_type = record.get("eventType")
    if event_type not in _OKTA_EVENT_ACTIONS:
        return None

    published = record.get("published")
    if not isinstance(published, str) or (ts := _parse_iso_datetime(published)) is None:
        return None

    actor_data = record.get("actor")
    actor_data = actor_data if isinstance(actor_data, dict) else {}
    client = record.get("client")
    client = client if isinstance(client, dict) else {}
    outcome = record.get("outcome")
    outcome = outcome if isinstance(outcome, dict) else {}
    auth_context = record.get("authenticationContext")
    auth_context = auth_context if isinstance(auth_context, dict) else {}

    user = (
        actor_data.get("alternateId")
        or actor_data.get("displayName")
        or actor_data.get("id")
        or ""
    )
    targets = record.get("target")
    first_target = (
        targets[0]
        if isinstance(targets, list) and targets and isinstance(targets[0], dict)
        else {}
    )
    target = (
        user
        or first_target.get("alternateId")
        or first_target.get("displayName")
        or first_target.get("id")
        or "unknown"
    )
    actor = client.get("ipAddress") or user or "unknown"

    outcome_result = str(outcome.get("result", "")).upper()
    if outcome_result == "SUCCESS":
        result = "success"
    elif outcome_result == "FAILURE":
        result = "failure"
    else:
        result = "unknown"

    user_agent_data = client.get("userAgent")
    if isinstance(user_agent_data, dict):
        user_agent = user_agent_data.get("rawUserAgent", "")
    else:
        user_agent = user_agent_data if isinstance(user_agent_data, str) else ""

    extra = {
        "event_id": record.get("uuid", ""),
        "event_type": event_type,
        "user": user,
        "display_message": record.get("displayMessage", ""),
        "outcome_reason": outcome.get("reason", ""),
        "user_agent": user_agent,
        "authentication_provider": auth_context.get("authenticationProvider", ""),
        "credential_type": auth_context.get("credentialType", ""),
    }
    return NormalizedEvent(
        ts=ts,
        actor=str(actor),
        action=_OKTA_EVENT_ACTIONS[event_type],
        target=str(target),
        result=result,
        source="okta",
        raw=json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        extra={
            key: value
            for key, value in extra.items()
            if value not in ("", None)
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


def _parse_okta_file(path: str) -> list[NormalizedEvent]:
    content = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    if not content.strip():
        return []

    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        records = []
        for line in content.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
    else:
        if isinstance(payload, list):
            records = [record for record in payload if isinstance(record, dict)]
        elif isinstance(payload, dict):
            records = [payload]
        else:
            records = []

    return [
        event
        for record in records
        if (event := parse_okta_record(record)) is not None
    ]


def parse_file(path: str, *, log_type: str = "sshd") -> list[NormalizedEvent]:
    """Parse a whole file using the selected log format."""
    if log_type == "evtx":
        return _parse_evtx_file(path)
    if log_type == "okta":
        return _parse_okta_file(path)
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
