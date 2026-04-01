from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ParsedLogEntry:
    line_number: int
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    endpoint: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    user_agent: Optional[str] = None
    event_type: Optional[str] = None
    message: Optional[str] = None
    raw_line: str = ""
    extra_fields: dict = field(default_factory=dict)


class BaseLogParser(ABC):
    """Base class for all log parsers."""

    @abstractmethod
    def can_parse(self, sample_lines: list[str]) -> float:
        """Return confidence score (0.0 to 1.0) that this parser can handle these logs."""
        ...

    @abstractmethod
    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        """Parse a single log line. Return None if line cannot be parsed."""
        ...

    def parse_lines(self, lines: list[str]) -> list[ParsedLogEntry]:
        entries = []
        for i, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            entry = self.parse_line(line, i)
            if entry:
                entries.append(entry)
        return entries
