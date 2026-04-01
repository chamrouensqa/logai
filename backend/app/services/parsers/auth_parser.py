import re
from datetime import datetime
from typing import Optional

from .base import BaseLogParser, ParsedLogEntry

# Common auth log patterns (syslog-style)
AUTH_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
    r"(?P<message>.*)"
)

FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
ACCEPTED_PASSWORD = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)
INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
)
SESSION_OPENED = re.compile(
    r"pam_unix\(\S+\):?\s+session opened for user (?P<user>\S+)"
)
SESSION_CLOSED = re.compile(
    r"pam_unix\(\S+\):?\s+session closed for user (?P<user>\S+)"
)
SUDO_COMMAND = re.compile(
    r"(?P<user>\S+)\s*:\s*.*COMMAND=(?P<command>.*)"
)
CONNECTION_CLOSED = re.compile(
    r"Connection closed by (?:authenticating user )?(?P<user>\S+)?\s*(?P<ip>[\d.]+)"
)


class AuthLogParser(BaseLogParser):
    """Parser for Linux auth.log / secure log files."""

    def can_parse(self, sample_lines: list[str]) -> float:
        matches = sum(1 for line in sample_lines if AUTH_PATTERN.match(line.strip()))
        if not sample_lines:
            return 0.0
        ratio = matches / len(sample_lines)
        auth_keywords = ["sshd", "sudo", "pam_unix", "Failed password", "Accepted password", "session opened"]
        keyword_hits = sum(1 for line in sample_lines for kw in auth_keywords if kw in line)
        if keyword_hits > 0 and ratio > 0.3:
            return min(0.95, ratio + 0.2)
        return ratio * 0.7

    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        match = AUTH_PATTERN.match(line)
        if not match:
            return ParsedLogEntry(
                line_number=line_number, raw_line=line,
                event_type="unknown", message=line,
            )

        timestamp_str = match.group("timestamp")
        try:
            ts = datetime.strptime(f"2026 {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = None

        message = match.group("message")
        service = match.group("service")
        entry = ParsedLogEntry(
            line_number=line_number,
            timestamp=ts,
            raw_line=line,
            message=message,
            extra_fields={"hostname": match.group("hostname"), "service": service},
        )

        if m := FAILED_PASSWORD.search(message):
            entry.event_type = "login_failed"
            entry.username = m.group("user")
            entry.source_ip = m.group("ip")
        elif m := ACCEPTED_PASSWORD.search(message):
            entry.event_type = "login_success"
            entry.username = m.group("user")
            entry.source_ip = m.group("ip")
        elif m := INVALID_USER.search(message):
            entry.event_type = "invalid_user"
            entry.username = m.group("user")
            entry.source_ip = m.group("ip")
        elif m := SESSION_OPENED.search(message):
            entry.event_type = "session_opened"
            entry.username = m.group("user")
        elif m := SESSION_CLOSED.search(message):
            entry.event_type = "session_closed"
            entry.username = m.group("user")
        elif m := SUDO_COMMAND.search(message):
            entry.event_type = "sudo_command"
            entry.username = m.group("user")
            entry.extra_fields["command"] = m.group("command").strip()
        elif m := CONNECTION_CLOSED.search(message):
            entry.event_type = "connection_closed"
            entry.username = m.group("user")
            entry.source_ip = m.group("ip")
        elif "Disconnected" in message or "disconnect" in message.lower():
            entry.event_type = "disconnected"
        else:
            entry.event_type = "auth_other"

        return entry
