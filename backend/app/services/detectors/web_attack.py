import re
from collections import defaultdict

from app.models.models import AlertType, Severity
from app.services.parsers.base import ParsedLogEntry
from .base import BaseDetector, DetectionResult

SQL_INJECTION_PATTERNS = [
    re.compile(r"(?:union\s+select|select\s+.*from|drop\s+table|insert\s+into|update\s+.*set)", re.I),
    re.compile(r"(?:or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s*'|'\s*--)", re.I),
    re.compile(r"(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", re.I),
    re.compile(r"(?:0x[0-9a-f]+|char\s*\(|concat\s*\()", re.I),
]

XSS_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.I),
    re.compile(r"(?:javascript|vbscript)\s*:", re.I),
    re.compile(r"(?:on(?:error|load|click|mouseover|focus|blur)\s*=)", re.I),
    re.compile(r"(?:alert|confirm|prompt)\s*\(", re.I),
    re.compile(r"document\.(?:cookie|write|location)", re.I),
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"(?:\.\./|\.\.\\){2,}"),
    re.compile(r"(?:/etc/passwd|/etc/shadow|/proc/self)", re.I),
    re.compile(r"(?:c:\\windows|c:\\boot\.ini)", re.I),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r"(?:;\s*(?:ls|cat|id|whoami|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby))", re.I),
    re.compile(r"(?:\|\s*(?:ls|cat|id|whoami|uname))", re.I),
    re.compile(r"(?:`[^`]+`|\$\([^)]+\))"),
]

SCANNER_PATTERNS = [
    re.compile(r"(?:nikto|nmap|sqlmap|burp|dirbuster|gobuster|wfuzz|hydra|nessus)", re.I),
    re.compile(r"(?:wp-admin|wp-login|wp-content|xmlrpc\.php)", re.I),
    re.compile(r"(?:\.env|\.git|\.svn|\.htaccess|web\.config|\.DS_Store)", re.I),
    re.compile(r"(?:phpmyadmin|adminer|phpinfo)", re.I),
]


class WebAttackDetector(BaseDetector):
    """Detect web-based attacks: SQL injection, XSS, path traversal, command injection, scanning."""

    def detect(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        results = []
        attack_events: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))

        for entry in entries:
            target = entry.endpoint or entry.message or entry.raw_line
            if not target:
                continue

            for category, patterns in [
                ("SQL Injection", SQL_INJECTION_PATTERNS),
                ("Cross-Site Scripting (XSS)", XSS_PATTERNS),
                ("Path Traversal", PATH_TRAVERSAL_PATTERNS),
                ("Command Injection", COMMAND_INJECTION_PATTERNS),
                ("Vulnerability Scanning", SCANNER_PATTERNS),
            ]:
                for pattern in patterns:
                    if pattern.search(target):
                        ip = entry.source_ip or "unknown"
                        attack_events[category][ip].append(entry)
                        break

        for category, ip_entries in attack_events.items():
            for ip, entries_list in ip_entries.items():
                count = len(entries_list)

                if category == "Vulnerability Scanning":
                    severity = Severity.MEDIUM if count > 10 else Severity.LOW
                elif count >= 20:
                    severity = Severity.CRITICAL
                elif count >= 10:
                    severity = Severity.HIGH
                elif count >= 3:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW

                sample_endpoints = list(set(
                    e.endpoint or e.message[:100] for e in entries_list[:5]
                ))

                results.append(DetectionResult(
                    alert_type=AlertType.WEB_ATTACK,
                    severity=severity,
                    title=f"{category} Attempt from {ip}",
                    description=(
                        f"Detected {count} {category.lower()} attempt(s) from IP {ip}. "
                        f"Sample targets: {', '.join(sample_endpoints[:3])}"
                    ),
                    source_ip=ip,
                    evidence={
                        "attack_type": category,
                        "attempt_count": count,
                        "source_ip": ip,
                        "sample_endpoints": sample_endpoints,
                        "sample_lines": [e.line_number for e in entries_list[:10]],
                    },
                    recommended_actions=[
                        f"Block IP {ip} at WAF/firewall level",
                        f"Review all requests from {ip} for successful exploitation",
                        "Check application logs for signs of data breach",
                        f"Update WAF rules to block {category.lower()} patterns",
                        "Ensure input validation and parameterized queries are in place",
                    ],
                ))

        return results
