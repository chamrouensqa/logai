import json
from datetime import datetime
from typing import Optional

from dateutil import parser as dateutil_parser

from .base import BaseLogParser, ParsedLogEntry

TIMESTAMP_FIELDS = ["timestamp", "time", "@timestamp", "datetime", "date", "created_at", "ts", "log_time"]
IP_FIELDS = ["ip", "source_ip", "src_ip", "client_ip", "remote_addr", "ipAddress", "sourceAddress"]
USER_FIELDS = ["user", "username", "user_name", "userId", "user_id", "account", "actor"]
ENDPOINT_FIELDS = ["endpoint", "path", "url", "uri", "request_uri", "route"]
METHOD_FIELDS = ["method", "http_method", "request_method", "verb"]
STATUS_FIELDS = ["status", "status_code", "statusCode", "http_status", "response_code"]
MESSAGE_FIELDS = ["message", "msg", "log", "description", "text", "detail"]
EVENT_FIELDS = ["event", "event_type", "eventType", "action", "type", "category"]
LEVEL_FIELDS = ["level", "severity", "log_level", "loglevel", "priority"]


def _find_field(data: dict, candidates: list[str]) -> Optional[str]:
    for key in candidates:
        if key in data:
            return str(data[key])
        lower_data = {k.lower(): v for k, v in data.items()}
        if key.lower() in lower_data:
            return str(lower_data[key.lower()])
    return None


def _parse_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return dateutil_parser.parse(value)
    except (ValueError, TypeError):
        return None


class JSONLogParser(BaseLogParser):
    """Parser for JSON-formatted log lines (one JSON object per line, or JSON arrays)."""

    def can_parse(self, sample_lines: list[str]) -> float:
        json_count = 0
        for line in sample_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, (dict, list)):
                    json_count += 1
            except (json.JSONDecodeError, ValueError):
                continue
        if not sample_lines:
            return 0.0
        return json_count / len(sample_lines)

    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        line = line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return ParsedLogEntry(
                line_number=line_number, raw_line=line,
                event_type="unparsed", message=line,
            )

        if isinstance(data, list):
            # JSON array — treat each element as a separate concern; just note it
            return ParsedLogEntry(
                line_number=line_number, raw_line=line,
                event_type="json_array", message=f"Array with {len(data)} elements",
                extra_fields={"array_length": len(data)},
            )

        ts_str = _find_field(data, TIMESTAMP_FIELDS)
        status_str = _find_field(data, STATUS_FIELDS)
        size_str = _find_field(data, ["size", "bytes", "content_length", "response_size"])
        level = _find_field(data, LEVEL_FIELDS)
        event_type = _find_field(data, EVENT_FIELDS)

        if not event_type and level:
            event_type = level.lower()

        try:
            status_code = int(status_str) if status_str else None
        except (ValueError, TypeError):
            status_code = None

        try:
            response_size = int(size_str) if size_str else None
        except (ValueError, TypeError):
            response_size = None

        standard_keys = set()
        for field_list in [TIMESTAMP_FIELDS, IP_FIELDS, USER_FIELDS, ENDPOINT_FIELDS,
                           METHOD_FIELDS, STATUS_FIELDS, MESSAGE_FIELDS, EVENT_FIELDS, LEVEL_FIELDS]:
            standard_keys.update(f.lower() for f in field_list)

        extra = {k: v for k, v in data.items() if k.lower() not in standard_keys}

        return ParsedLogEntry(
            line_number=line_number,
            timestamp=_parse_timestamp(ts_str),
            source_ip=_find_field(data, IP_FIELDS),
            username=_find_field(data, USER_FIELDS),
            endpoint=_find_field(data, ENDPOINT_FIELDS),
            method=_find_field(data, METHOD_FIELDS),
            status_code=status_code,
            response_size=response_size,
            event_type=event_type or "log_entry",
            message=_find_field(data, MESSAGE_FIELDS) or line[:500],
            raw_line=line,
            extra_fields=extra,
        )
