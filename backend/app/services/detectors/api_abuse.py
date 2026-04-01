from collections import defaultdict
from datetime import timedelta

from app.models.models import AlertType, Severity
from app.services.parsers.base import ParsedLogEntry
from .base import BaseDetector, DetectionResult

REQUESTS_PER_MINUTE_THRESHOLD = 100
DATA_EXFILTRATION_THRESHOLD_MB = 50


class APIAbuseDetector(BaseDetector):
    """Detect API abuse: rate limit violations, excessive data transfer."""

    def detect(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        results = []
        results.extend(self._detect_rate_abuse(entries))
        results.extend(self._detect_data_exfiltration(entries))
        results.extend(self._detect_error_flooding(entries))
        return results

    def _detect_rate_abuse(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        results = []
        ip_requests: dict[str, list[ParsedLogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.source_ip and entry.timestamp:
                ip_requests[entry.source_ip].append(entry)

        for ip, reqs in ip_requests.items():
            reqs.sort(key=lambda e: e.timestamp)
            max_rate, window_start, window_end = self._find_peak_rate(reqs)

            if max_rate >= REQUESTS_PER_MINUTE_THRESHOLD:
                if max_rate >= 500:
                    severity = Severity.CRITICAL
                elif max_rate >= 300:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                results.append(DetectionResult(
                    alert_type=AlertType.API_ABUSE,
                    severity=severity,
                    title=f"API Rate Abuse from {ip}",
                    description=(
                        f"IP {ip} made {max_rate} requests per minute "
                        f"(threshold: {REQUESTS_PER_MINUTE_THRESHOLD}/min). "
                        f"Peak window: {window_start} to {window_end}."
                    ),
                    source_ip=ip,
                    evidence={
                        "peak_rate_per_minute": max_rate,
                        "total_requests": len(reqs),
                        "window_start": str(window_start),
                        "window_end": str(window_end),
                    },
                    recommended_actions=[
                        f"Apply rate limiting to IP {ip}",
                        "Implement API throttling at the gateway level",
                        "Consider CAPTCHA or proof-of-work challenges",
                        "Check if this is a DDoS pattern",
                    ],
                ))

        return results

    def _detect_data_exfiltration(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        results = []
        ip_data: dict[str, int] = defaultdict(int)
        ip_entries: dict[str, list] = defaultdict(list)

        for entry in entries:
            if entry.source_ip and entry.response_size:
                ip_data[entry.source_ip] += entry.response_size
                ip_entries[entry.source_ip].append(entry)

        threshold_bytes = DATA_EXFILTRATION_THRESHOLD_MB * 1024 * 1024

        for ip, total_bytes in ip_data.items():
            if total_bytes >= threshold_bytes:
                mb = total_bytes / (1024 * 1024)

                if mb >= 500:
                    severity = Severity.CRITICAL
                elif mb >= 200:
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM

                top_endpoints = defaultdict(int)
                for e in ip_entries[ip]:
                    if e.endpoint:
                        top_endpoints[e.endpoint] += e.response_size or 0
                sorted_eps = sorted(top_endpoints.items(), key=lambda x: x[1], reverse=True)[:5]

                results.append(DetectionResult(
                    alert_type=AlertType.DATA_EXFILTRATION,
                    severity=severity,
                    title=f"Possible Data Exfiltration by {ip}",
                    description=(
                        f"IP {ip} downloaded {mb:.1f} MB of data across {len(ip_entries[ip])} requests. "
                        f"Top endpoints: {', '.join(ep for ep, _ in sorted_eps[:3])}"
                    ),
                    source_ip=ip,
                    evidence={
                        "total_bytes": total_bytes,
                        "total_mb": round(mb, 1),
                        "request_count": len(ip_entries[ip]),
                        "top_endpoints": [{"endpoint": ep, "bytes": b} for ep, b in sorted_eps],
                    },
                    recommended_actions=[
                        f"Investigate what data IP {ip} accessed",
                        "Check for sensitive data in transferred content",
                        "Review access controls on data endpoints",
                        "Consider data loss prevention (DLP) controls",
                    ],
                ))

        return results

    def _detect_error_flooding(self, entries: list[ParsedLogEntry]) -> list[DetectionResult]:
        """Detect IPs generating excessive 4xx/5xx errors (probing)."""
        results = []
        ip_errors: dict[str, list[ParsedLogEntry]] = defaultdict(list)

        for entry in entries:
            if entry.source_ip and entry.status_code and entry.status_code >= 400:
                ip_errors[entry.source_ip].append(entry)

        for ip, errors in ip_errors.items():
            if len(errors) < 50:
                continue

            status_dist = defaultdict(int)
            for e in errors:
                status_dist[e.status_code] += 1

            four_xx = sum(v for k, v in status_dist.items() if 400 <= k < 500)
            five_xx = sum(v for k, v in status_dist.items() if k >= 500)

            if four_xx >= 50:
                results.append(DetectionResult(
                    alert_type=AlertType.API_ABUSE,
                    severity=Severity.MEDIUM,
                    title=f"Excessive Client Errors from {ip}",
                    description=(
                        f"IP {ip} generated {four_xx} client errors (4xx) and {five_xx} server errors (5xx). "
                        f"This may indicate directory brute-forcing or vulnerability scanning."
                    ),
                    source_ip=ip,
                    evidence={
                        "4xx_count": four_xx,
                        "5xx_count": five_xx,
                        "status_distribution": dict(status_dist),
                        "total_errors": len(errors),
                    },
                    recommended_actions=[
                        f"Block or rate-limit IP {ip}",
                        "Review error patterns for reconnaissance activity",
                        "Ensure sensitive paths return generic responses",
                    ],
                ))

        return results

    def _find_peak_rate(self, sorted_entries: list[ParsedLogEntry]) -> tuple[int, str, str]:
        if not sorted_entries:
            return (0, "", "")

        window = timedelta(minutes=1)
        max_rate = 0
        best_start = sorted_entries[0].timestamp
        best_end = sorted_entries[0].timestamp
        start_idx = 0

        for end_idx in range(len(sorted_entries)):
            while sorted_entries[end_idx].timestamp - sorted_entries[start_idx].timestamp > window:
                start_idx += 1

            rate = end_idx - start_idx + 1
            if rate > max_rate:
                max_rate = rate
                best_start = sorted_entries[start_idx].timestamp
                best_end = sorted_entries[end_idx].timestamp

        return (max_rate, str(best_start), str(best_end))
