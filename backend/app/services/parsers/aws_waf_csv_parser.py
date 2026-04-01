"""Parser for AWS WAF logs exported as CSV (e.g. from Athena / S3 / Kinesis export)."""
import csv
from datetime import datetime, timezone
from typing import Optional

from .base import BaseLogParser, ParsedLogEntry


def _row_get(row: dict, *names: str) -> str:
    for n in names:
        for k, v in row.items():
            if k and k.strip().lower() == n.lower():
                if v is None:
                    return ""
                return str(v).strip()
    return ""


class AwsWafCsvParser(BaseLogParser):
    """Parses AWS WAF CSV exports with columns like timestamp, action, host, uri, httpMethod, clientIp."""

    def can_parse(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        first = sample_lines[0].strip().lower()
        if not first.startswith("timestamp,"):
            return 0.0
        head = first[:3000]
        if "clientip" in head and "uri" in head and "httpmethod" in head:
            return 0.98
        return 0.0

    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        return None

    def parse_csv_file(self, file_path: str) -> list[ParsedLogEntry]:
        entries: list[ParsedLogEntry] = []
        with open(file_path, "r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return entries

            for row_num, row in enumerate(reader, start=2):
                ts_raw = _row_get(row, "timestamp", "@timestamp", "time")
                ts = self._parse_timestamp(ts_raw)

                action = _row_get(row, "action").upper()
                uri = _row_get(row, "uri", "path")
                method = _row_get(row, "httpmethod", "method")
                client_ip = _row_get(row, "clientip", "client_ip", "sourceip", "ip")
                host = _row_get(row, "host", "hostname")
                country = _row_get(row, "country")
                rule = _row_get(row, "terminatingruleid", "rule", "terminating_rule_id")

                if action == "BLOCK":
                    event_type = "waf_block"
                elif action == "ALLOW":
                    event_type = "waf_allow"
                elif action == "COUNT":
                    event_type = "waf_count"
                else:
                    event_type = "waf_event"

                msg = f"{method} {uri} action={action}"
                if rule:
                    msg += f" rule={rule}"

                entries.append(
                    ParsedLogEntry(
                        line_number=row_num,
                        timestamp=ts,
                        source_ip=client_ip or None,
                        endpoint=uri or None,
                        method=method or None,
                        event_type=event_type,
                        message=msg[:2000],
                        raw_line="",
                        extra_fields={
                            "host": host,
                            "country": country,
                            "action": action,
                            "terminating_rule": rule,
                        },
                    )
                )

        return entries

    def _parse_timestamp(self, raw: str) -> Optional[datetime]:
        if not raw:
            return None
        s = str(raw).strip()
        try:
            if s.isdigit():
                ms = int(s)
                if ms > 1_000_000_000_000:
                    ms = ms // 1000
                return datetime.fromtimestamp(ms, tz=timezone.utc).replace(tzinfo=None)
            return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, OSError, OverflowError):
            return None
