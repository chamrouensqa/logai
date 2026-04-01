from collections import defaultdict
from datetime import datetime

from app.models.models import AlertType, Severity
from app.services.parsers.base import ParsedLogEntry
from .base import BaseDetector, DetectionResult

WORKING_HOURS_START = 6
WORKING_HOURS_END = 22
PRIVILEGED_ACCOUNTS = {"root", "admin", "administrator", "sysadmin", "superuser"}


class SuspiciousLoginDetector(BaseDetector):
    """Detect suspicious login patterns:
    - Admin logins outside working hours
    - Logins to privileged accounts from unusual IPs
    - Successful login after many failures
    """

    def detect(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        results = []
        results.extend(self._detect_off_hours_admin(entries))
        results.extend(self._detect_privilege_access_patterns(entries))
        results.extend(self._detect_login_after_failure(entries))
        return results

    def _detect_off_hours_admin(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        results = []
        for entry in entries:
            if (
                entry.event_type in ("login_success", "session_opened")
                and entry.username
                and entry.username.lower() in PRIVILEGED_ACCOUNTS
                and entry.timestamp
            ):
                hour = entry.timestamp.hour
                if hour < WORKING_HOURS_START or hour >= WORKING_HOURS_END:
                    results.append(DetectionResult(
                        alert_type=AlertType.SUSPICIOUS_LOGIN,
                        severity=Severity.HIGH,
                        title=f"Privileged Account Login Outside Working Hours",
                        description=(
                            f"User '{entry.username}' logged in at {entry.timestamp.strftime('%H:%M:%S')} "
                            f"(outside {WORKING_HOURS_START}:00-{WORKING_HOURS_END}:00 working hours)"
                            + (f" from IP {entry.source_ip}" if entry.source_ip else "")
                            + ". This may indicate unauthorized access."
                        ),
                        source_ip=entry.source_ip,
                        target_account=entry.username,
                        evidence={
                            "login_time": str(entry.timestamp),
                            "hour": hour,
                            "account": entry.username,
                            "source_ip": entry.source_ip,
                            "line_number": entry.line_number,
                        },
                        recommended_actions=[
                            f"Verify this login was authorized by the {entry.username} account owner",
                            "Check for any lateral movement or privilege escalation",
                            "Review session activity following this login",
                            "Consider restricting privileged account access to working hours",
                        ],
                    ))
        return results

    def _detect_privilege_access_patterns(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        """Detect multiple privileged account accesses from a single IP."""
        results = []
        ip_priv_logins: dict[str, list[ParsedLogEntry]] = defaultdict(list)

        for entry in entries:
            if (
                entry.event_type in ("login_success", "session_opened", "sudo_command")
                and entry.username
                and entry.username.lower() in PRIVILEGED_ACCOUNTS
                and entry.source_ip
            ):
                ip_priv_logins[entry.source_ip].append(entry)

        for ip, logins in ip_priv_logins.items():
            accounts = set(e.username for e in logins)
            if len(accounts) > 1:
                results.append(DetectionResult(
                    alert_type=AlertType.PRIVILEGE_ESCALATION,
                    severity=Severity.CRITICAL,
                    title=f"Multiple Privileged Account Access from {ip}",
                    description=(
                        f"IP {ip} accessed {len(accounts)} privileged accounts: "
                        f"{', '.join(accounts)}. This may indicate credential stuffing or lateral movement."
                    ),
                    source_ip=ip,
                    target_account=", ".join(accounts),
                    evidence={
                        "accounts": list(accounts),
                        "login_count": len(logins),
                        "source_ip": ip,
                    },
                    recommended_actions=[
                        f"Block IP {ip} and investigate source",
                        "Reset passwords for all affected privileged accounts",
                        "Audit all actions taken by these accounts",
                        "Enable MFA for all privileged accounts",
                    ],
                ))

        return results

    def _detect_login_after_failure(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        """Detect successful logins that follow a series of failures for the same user."""
        results = []
        user_events: dict[str, list[ParsedLogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.username and entry.event_type in (
                "login_failed", "login_success", "session_opened", "invalid_user"
            ):
                user_events[entry.username].append(entry)

        for user, events in user_events.items():
            timed_events = [e for e in events if e.timestamp]
            timed_events.sort(key=lambda e: e.timestamp)

            failure_streak = 0
            for event in timed_events:
                if event.event_type in ("login_failed", "invalid_user"):
                    failure_streak += 1
                elif event.event_type in ("login_success", "session_opened"):
                    if failure_streak >= 5:
                        results.append(DetectionResult(
                            alert_type=AlertType.SUSPICIOUS_LOGIN,
                            severity=Severity.HIGH,
                            title=f"Successful Login After {failure_streak} Failures for '{user}'",
                            description=(
                                f"Account '{user}' had {failure_streak} consecutive failed login attempts "
                                f"before a successful login at {event.timestamp}. "
                                f"This may indicate a successful brute-force or credential guessing attack."
                            ),
                            source_ip=event.source_ip,
                            target_account=user,
                            evidence={
                                "failure_count": failure_streak,
                                "success_time": str(event.timestamp),
                                "success_ip": event.source_ip,
                                "line_number": event.line_number,
                            },
                            recommended_actions=[
                                f"Immediately investigate the session for user '{user}'",
                                "Force password reset for this account",
                                "Check for data access or lateral movement",
                                "Enable MFA if not already enabled",
                            ],
                        ))
                    failure_streak = 0

        return results
