"""Parsers for supported security log formats."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator
from xml.etree import ElementTree

from ai_soc_agent.normalizer import NormalizedEvent

logger = logging.getLogger(__name__)

# OpenSSH auth.log pattern (Debian / Ubuntu).
# Example: "Jul 23 22:01:14 host sshd[1234]: Failed password for invalid user
# root from 203.0.113.45 port 51234 ssh2"
_SSHD_RE = re.compile(
    r"^(?P<ts>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<msg>.+)$"
)

# Covers password, publickey, and keyboard-interactive/pam in one shape. Only
# password auth used to be recognized, so key-based logins — successful ones
# especially — were invisible to the lateral-movement and geo rules.
_AUTH_RESULT_RE = re.compile(
    r"(?P<outcome>Failed|Accepted)\s+(?P<method>password|publickey|keyboard-interactive/pam|none)"
    r"\s+for(?:\s+invalid user)?\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

# "Invalid user admin from 203.0.113.45 port 51234" — emitted before any auth
# attempt, and a strong brute-force/enumeration signal on its own.
_INVALID_USER_RE = re.compile(
    r"Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?"
)

# "Connection closed by authenticating user root 203.0.113.45 port 51234 [preauth]"
_PREAUTH_CLOSE_RE = re.compile(
    r"Connection (?:closed|reset) by (?:authenticating|invalid) user\s+(?P<user>\S+)\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

_AUTH_OUTCOMES = {"Failed": "failure", "Accepted": "success"}

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

_OKTA_EVENT_ACTIONS = {
    "user.session.start": "okta_login",
    "user.authentication.auth_via_mfa": "okta_mfa",
    "user.authentication.sso": "okta_sso",
}


def _parse_ts(token: str, year: int | None = None) -> datetime:
    """Parse 'Mon DD HH:MM:SS' into a datetime; year defaults to current."""
    if year is None:
        year = datetime.now().year
    return datetime.strptime(f"{year} {token}", "%Y %b %d %H:%M:%S")


class _SyslogYear:
    """Assign years to syslog lines, which carry only 'Mon DD HH:MM:SS'.

    Two failure modes this exists to avoid:

    - A file spanning New Year would jump backwards by a year mid-stream,
      scrambling every time-window rule. A month going backwards means the
      year rolled forward.
    - Parsing December logs on 2 January stamped them with the new year, i.e.
      eleven months in the future. If the first record's month is ahead of the
      current month, the log started in the previous year.
    """

    def __init__(self, year: int | None = None) -> None:
        self._explicit = year is not None
        self._year = year if year is not None else datetime.now().year
        self._previous_month: int | None = None

    def resolve(self, token: str) -> datetime:
        """Return the datetime for one syslog timestamp token."""
        month = _MONTHS.get(token[:3])
        if month is None:
            return _parse_ts(token, year=self._year)
        if self._previous_month is None:
            if not self._explicit and month > datetime.now().month:
                self._year -= 1
        elif month < self._previous_month:
            self._year += 1
        self._previous_month = month
        return _parse_ts(token, year=self._year)


_MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


def parse_line(line: str, *, year: int | None = None) -> NormalizedEvent | None:
    """Parse one log line. Returns None if the line doesn't match a known format."""
    line = line.rstrip("\n")
    m = _SSHD_RE.match(line)
    if m is None:
        return None

    msg = m.group("msg")
    ts = _parse_ts(m.group("ts"), year=year)
    host = m.group("host")

    def _event(
        *, ip: str, user: str, result: str, port: str | None, **extra: Any
    ) -> NormalizedEvent:
        fields: dict[str, Any] = {"host": host, **extra}
        if port is not None:
            fields["port"] = int(port)
        return NormalizedEvent(
            ts=ts,
            actor=ip,
            action="ssh_login",
            target=user,
            result=result,
            source="sshd",
            raw=line,
            extra=fields,
        )

    if (am := _AUTH_RESULT_RE.search(msg)) is not None:
        return _event(
            ip=am.group("ip"),
            user=am.group("user"),
            result=_AUTH_OUTCOMES[am.group("outcome")],
            port=am.group("port"),
            auth_method=am.group("method"),
        )

    if (im := _INVALID_USER_RE.search(msg)) is not None:
        return _event(
            ip=im.group("ip"),
            user=im.group("user"),
            result="failure",
            port=im.group("port"),
            reason="invalid_user",
        )

    if (pm := _PREAUTH_CLOSE_RE.search(msg)) is not None:
        return _event(
            ip=pm.group("ip"),
            user=pm.group("user"),
            result="failure",
            port=pm.group("port"),
            reason="preauth_close",
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
    target_label = (
        first_target.get("displayName")
        or first_target.get("alternateId")
        or first_target.get("id")
        or ""
    )
    # For SSO the interesting target is the application, not the person doing
    # the signing in — reporting the user there threw away the only field that
    # says what was accessed. Login/MFA events have no app, so they keep the user.
    if event_type == "user.authentication.sso" and target_label:
        target = target_label
    else:
        target = user or target_label or "unknown"
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
        "target_app": target_label,
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


def _iter_evtx_file(path: str) -> Iterator[NormalizedEvent]:
    """Stream Windows Event records without holding the file in memory.

    ``iterparse`` frees each element after use; the previous implementation
    read the whole file plus built a full element list, so a multi-gigabyte
    export could not be parsed at all.
    """
    try:
        for _, element in ElementTree.iterparse(path, events=("end",)):
            if _local_name(element.tag) != "Event":
                continue
            event = _parse_evtx_element(element)
            element.clear()
            if event is not None:
                yield event
    except ElementTree.ParseError:
        # Not a single well-formed document: fall back to one record per line.
        with open(path, encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                if line.strip() and (event := parse_evtx_line(line)) is not None:
                    yield event


def _iter_okta_file(path: str) -> Iterator[NormalizedEvent]:
    """Stream Okta records, preferring JSONL and falling back to a JSON array."""
    with open(path, encoding="utf-8-sig", errors="replace") as handle:
        first = handle.readline()
        if not first.strip():
            return
        if first.lstrip().startswith(("[", "{")) and not _is_json_object_line(first):
            # A pretty-printed array or object spans lines; it has to be loaded.
            yield from _parse_okta_document(path)
            return
        handle.seek(0)
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("skipping malformed okta line in %s", path)
                continue
            if isinstance(record, dict) and (event := parse_okta_record(record)) is not None:
                yield event


def _is_json_object_line(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except json.JSONDecodeError:
        return False


def _parse_okta_document(path: str) -> Iterator[NormalizedEvent]:
    content = Path(path).read_text(encoding="utf-8-sig", errors="replace")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        logger.warning("okta file %s is neither JSONL nor a JSON document", path)
        return
    records = (
        [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, list)
        else [payload]
        if isinstance(payload, dict)
        else []
    )
    for record in records:
        if (event := parse_okta_record(record)) is not None:
            yield event


def _iter_line_file(path: str, log_type: str) -> Iterator[NormalizedEvent]:
    if log_type == "sshd":
        years = _SyslogYear()

        def parse(line: str) -> NormalizedEvent | None:
            match = _SSHD_RE.match(line.rstrip("\n"))
            if match is None:
                return None
            return parse_line(line, year=years.resolve(match.group("ts")).year)
    else:
        parse = parse_nginx_line

    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            if (event := parse(line)) is not None:
                yield event


def iter_file(path: str, *, log_type: str = "sshd") -> Iterator[NormalizedEvent]:
    """Yield events from a file without materializing the whole log."""
    if log_type == "evtx":
        return _iter_evtx_file(path)
    if log_type == "okta":
        return _iter_okta_file(path)
    if log_type not in ("sshd", "nginx"):
        raise ValueError(f"Unsupported log type: {log_type}")
    return _iter_line_file(path, log_type)


def parse_file(path: str, *, log_type: str = "sshd") -> list[NormalizedEvent]:
    """Parse a whole file using the selected log format."""
    return list(iter_file(path, log_type=log_type))
