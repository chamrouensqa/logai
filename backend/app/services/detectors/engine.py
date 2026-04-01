from app.services.parsers.base import ParsedLogEntry
from .base import DetectionResult
from .brute_force import BruteForceDetector
from .suspicious_login import SuspiciousLoginDetector
from .web_attack import WebAttackDetector
from .api_abuse import APIAbuseDetector


class DetectionEngine:
    """Runs all security detectors against parsed log entries."""

    def __init__(self):
        self.detectors = [
            BruteForceDetector(),
            SuspiciousLoginDetector(),
            WebAttackDetector(),
            APIAbuseDetector(),
        ]

    def run_all(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        all_results: list[DetectionResult] = []
        for detector in self.detectors:
            try:
                results = detector.detect(entries)
                all_results.extend(results)
            except Exception as e:
                all_results.append(DetectionResult(
                    alert_type=detector.__class__.__name__,
                    severity="medium",
                    title=f"Detection error in {detector.__class__.__name__}",
                    description=f"Error running detector: {str(e)}",
                ))
        return sorted(all_results, key=lambda r: self._severity_order(r.severity), reverse=True)

    def _severity_order(self, severity) -> int:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        if hasattr(severity, "value"):
            return order.get(severity.value, 0)
        return order.get(str(severity).lower(), 0)
