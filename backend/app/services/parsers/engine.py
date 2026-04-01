from typing import Optional

from .base import BaseLogParser, ParsedLogEntry
from .auth_parser import AuthLogParser
from .nginx_parser import NginxAccessParser, NginxErrorParser
from .json_parser import JSONLogParser
from .firewall_parser import FirewallLogParser
from .aws_waf_csv_parser import AwsWafCsvParser

# CSV / structured exports first — avoids mis-detecting AWS WAF CSV as JSON lines
ALL_PARSERS: list[BaseLogParser] = [
    AwsWafCsvParser(),
    AuthLogParser(),
    NginxAccessParser(),
    NginxErrorParser(),
    JSONLogParser(),
    FirewallLogParser(),
]


class LogParsingEngine:
    """Auto-detects log format and parses log files."""

    def __init__(self):
        self.parsers = ALL_PARSERS

    def detect_parser(self, lines: list[str], hint: Optional[str] = None) -> BaseLogParser:
        """Detect the best parser for the given log lines.

        Args:
            lines: Sample lines from the log file.
            hint: Optional log type hint (e.g., "auth", "nginx", "json", "firewall").
        """
        if hint:
            hint_map = {
                "auth": AuthLogParser,
                "syslog": AuthLogParser,
                "secure": AuthLogParser,
                "nginx": NginxAccessParser,
                "apache": NginxAccessParser,
                "access": NginxAccessParser,
                "nginx_error": NginxErrorParser,
                "json": JSONLogParser,
                "jsonl": JSONLogParser,
                "firewall": FirewallLogParser,
                "iptables": FirewallLogParser,
                "ufw": FirewallLogParser,
                "aws_waf": AwsWafCsvParser,
                "waf": AwsWafCsvParser,
                "csv": AwsWafCsvParser,
            }
            parser_cls = hint_map.get(hint.lower())
            if parser_cls:
                return parser_cls()

        sample = [l.strip() for l in lines[:100] if l.strip()]
        if not sample:
            return JSONLogParser()  # fallback

        best_parser = None
        best_score = 0.0

        for parser in self.parsers:
            try:
                score = parser.can_parse(sample)
                if score > best_score:
                    best_score = score
                    best_parser = parser
            except Exception:
                continue

        return best_parser or JSONLogParser()

    def parse_file(
        self,
        file_path: str,
        log_type_hint: Optional[str] = None,
        max_lines: Optional[int] = None,
    ) -> tuple[list[ParsedLogEntry], str]:
        """Parse a log file and return (entries, detected_log_type).

        Returns:
            Tuple of (parsed entries list, detected log type name).
        """
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if max_lines:
            lines = lines[:max_lines]

        parser = self.detect_parser(lines, hint=log_type_hint)
        log_type = type(parser).__name__.replace("Parser", "").replace("Log", "")

        if isinstance(parser, AwsWafCsvParser):
            return parser.parse_csv_file(file_path), log_type

        entries = []
        for i, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            entry = parser.parse_line(line, i)
            if entry:
                entries.append(entry)

        return entries, log_type

    def get_log_type_name(self, parser: BaseLogParser) -> str:
        return type(parser).__name__.replace("Parser", "").replace("Log", "")
