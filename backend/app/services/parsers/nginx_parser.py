import re
from datetime import datetime
from typing import Optional

from .base import BaseLogParser, ParsedLogEntry

# Combined Log Format (Nginx / Apache)
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://ref.com" "Mozilla/5"
ACCESS_LOG_PATTERN = re.compile(
    r'(?P<ip>[\d.]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<endpoint>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)\s*'
    r'(?:"(?P<referrer>[^"]*)")?\s*'
    r'(?:"(?P<user_agent>[^"]*)")?'
)

# Nginx error log
# 2024/01/15 10:30:00 [error] 12345#0: *1 message, client: 1.2.3.4, ...
ERROR_LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+'
    r'(?P<pid>\d+)#\d+:\s+'
    r'(?:\*\d+\s+)?'
    r'(?P<message>.*)'
)


class NginxAccessParser(BaseLogParser):
    """Parser for Nginx/Apache access logs (Combined Log Format)."""

    def can_parse(self, sample_lines: list[str]) -> float:
        matches = sum(1 for line in sample_lines if ACCESS_LOG_PATTERN.match(line.strip()))
        if not sample_lines:
            return 0.0
        return matches / len(sample_lines)

    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        match = ACCESS_LOG_PATTERN.match(line)
        if not match:
            return ParsedLogEntry(
                line_number=line_number, raw_line=line,
                event_type="unparsed", message=line,
            )

        timestamp_str = match.group("timestamp")
        try:
            ts = datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                ts = datetime.strptime(timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                ts = None

        status = int(match.group("status"))
        size_str = match.group("size")
        size = int(size_str) if size_str and size_str != "-" else None
        user = match.group("user")
        if user == "-":
            user = None

        event_type = self._classify_request(status, match.group("method"), match.group("endpoint"))

        return ParsedLogEntry(
            line_number=line_number,
            timestamp=ts,
            source_ip=match.group("ip"),
            username=user,
            endpoint=match.group("endpoint"),
            method=match.group("method"),
            status_code=status,
            response_size=size,
            user_agent=match.group("user_agent"),
            event_type=event_type,
            message=f'{match.group("method")} {match.group("endpoint")} -> {status}',
            raw_line=line,
            extra_fields={
                "referrer": match.group("referrer") or "",
                "protocol": match.group("protocol"),
            },
        )

    def _classify_request(self, status: int, method: str, endpoint: str) -> str:
        if status == 401:
            return "unauthorized"
        if status == 403:
            return "forbidden"
        if status == 404:
            return "not_found"
        if status >= 500:
            return "server_error"
        if status >= 400:
            return "client_error"
        if any(pattern in endpoint.lower() for pattern in ["/login", "/auth", "/signin"]):
            return "authentication"
        if any(pattern in endpoint.lower() for pattern in ["/admin", "/dashboard", "/manage"]):
            return "admin_access"
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            return "modification"
        return "access"


class NginxErrorParser(BaseLogParser):
    """Parser for Nginx error logs."""

    def can_parse(self, sample_lines: list[str]) -> float:
        matches = sum(1 for line in sample_lines if ERROR_LOG_PATTERN.match(line.strip()))
        if not sample_lines:
            return 0.0
        return matches / len(sample_lines)

    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        match = ERROR_LOG_PATTERN.match(line)
        if not match:
            return None

        timestamp_str = match.group("timestamp")
        try:
            ts = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            ts = None

        message = match.group("message")
        ip_match = re.search(r"client:\s*([\d.]+)", message)
        source_ip = ip_match.group(1) if ip_match else None

        return ParsedLogEntry(
            line_number=line_number,
            timestamp=ts,
            source_ip=source_ip,
            event_type=f"error_{match.group('level')}",
            message=message,
            raw_line=line,
            extra_fields={"level": match.group("level"), "pid": match.group("pid")},
        )
