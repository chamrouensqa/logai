from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from app.models.models import AlertType, Severity
from app.services.parsers.base import ParsedLogEntry


@dataclass
class DetectionResult:
    alert_type: AlertType
    severity: Severity
    title: str
    description: str
    source_ip: Optional[str] = None
    target_account: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    recommended_actions: list[str] = field(default_factory=list)


class BaseDetector(ABC):
    """Base class for all security detectors."""

    @abstractmethod
    def detect(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        ...
