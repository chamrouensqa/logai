from collections import defaultdict
from datetime import timedelta

from app.models.models import AlertType, Severity
from app.services.parsers.base import ParsedLogEntry
from .base import BaseDetector, DetectionResult

FAILED_THRESHOLD = 10
TIME_WINDOW_MINUTES = 5
CRITICAL_THRESHOLD = 50


class BruteForceDetector(BaseDetector):
    """Detect brute-force login attempts: many failed logins from a single IP in a short window."""

    def detect(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        results = []
        failed_by_ip: dict[str, list[ParsedLogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.event_type in ("login_failed", "unauthorized", "invalid_user") and entry.source_ip:
                failed_by_ip[entry.source_ip].append(entry)

        for ip, failures in failed_by_ip.items():
            if len(failures) < FAILED_THRESHOLD:
                continue

            timed_failures = [f for f in failures if f.timestamp]
            if timed_failures:
                timed_failures.sort(key=lambda e: e.timestamp)
                windows = self._find_burst_windows(timed_failures)
            else:
                windows = [(failures, len(failures))]

            for window_entries, count in windows:
                if count < FAILED_THRESHOLD:
                    continue

                targets = set(e.username for e in window_entries if e.username)
                first_ts = window_entries[0].timestamp
                last_ts = window_entries[-1].timestamp
                duration = (last_ts - first_ts).total_seconds() if first_ts and last_ts else 0

                if count >= CRITICAL_THRESHOLD:
                    severity = Severity.CRITICAL
                elif count >= 30:
                    severity = Severity.HIGH
                elif count >= 20:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                success_after = self._check_success_after_failures(entries, ip, last_ts)
                if success_after:
                    severity = Severity.CRITICAL

                results.append(DetectionResult(
                    alert_type=AlertType.BRUTE_FORCE,
                    severity=severity,
                    title=f"Brute Force Attack from {ip}",
                    description=(
                        f"Detected {count} failed login attempts from IP {ip} "
                        f"within {duration:.0f} seconds. "
                        f"Target accounts: {', '.join(targets) or 'unknown'}."
                        + (" A SUCCESSFUL LOGIN was detected after the failures — possible credential compromise!" if success_after else "")
                    ),
                    source_ip=ip,
                    target_account=", ".join(targets) if targets else None,
                    evidence={
                        "failed_attempts": count,
                        "duration_seconds": duration,
                        "target_accounts": list(targets),
                        "first_attempt": str(first_ts) if first_ts else None,
                        "last_attempt": str(last_ts) if last_ts else None,
                        "success_after_failures": success_after,
                        "sample_lines": [e.line_number for e in window_entries[:10]],
                    },
                    recommended_actions=[
                        f"Block IP address {ip} immediately",
                        "Reset passwords for targeted accounts" if targets else "Review targeted accounts",
                        "Enable account lockout policies",
                        "Enable multi-factor authentication",
                        "Review successful login sessions from this IP" if success_after else "Monitor for successful login attempts",
                    ],
                ))

        return results

    def _find_burst_windows(self, sorted_entries: list[ParsedLogEntry]) -> list[tuple[list, int]]:
        """Find burst windows where failures cluster within TIME_WINDOW_MINUTES."""
        windows = []
        window_start = 0
        window = timedelta(minutes=TIME_WINDOW_MINUTES)

        for i in range(len(sorted_entries)):
            while (
                window_start < i
                and sorted_entries[i].timestamp - sorted_entries[window_start].timestamp > window
            ):
                window_start += 1

            count = i - window_start + 1
            if count >= FAILED_THRESHOLD and (
                not windows or sorted_entries[i].timestamp != windows[-1][0][-1].timestamp
            ):
                windows.append((sorted_entries[window_start:i + 1], count))

        # Deduplicate overlapping windows — keep the largest
        if not windows:
            return []
        windows.sort(key=lambda w: w[1], reverse=True)
        return [windows[0]]

    def _check_success_after_failures(self, all_entries: list, ip: str, last_failure_time) -> bool:
        if not last_failure_time:
            return False
        for entry in all_entries:
            if (
                entry.event_type in ("login_success", "session_opened")
                and entry.source_ip == ip
                and entry.timestamp
                and entry.timestamp > last_failure_time
            ):
                return True
        return False
