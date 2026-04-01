import re
from datetime import datetime
from typing import Optional

from .base import BaseLogParser, ParsedLogEntry

# iptables / netfilter log
# Mar 11 02:14:33 server kernel: [UFW BLOCK] IN=eth0 ... SRC=1.2.3.4 DST=5.6.7.8 ...PROTO=TCP SPT=12345 DPT=22
IPTABLES_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+kernel:\s+"
    r"(?:\[\s*[\d.]+\]\s*)?"
    r"(?:\[(?P<action>[^\]]+)\]\s*)?"
    r"(?P<message>.*)"
)

# Generic firewall key=value pairs
KV_PATTERN = re.compile(r"(\w+)=([\S]+)")

# PF (BSD/macOS) log
PF_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r".*rule\s+\d+.*\s+(?P<action>pass|block)\s+(?P<direction>in|out)\s+on\s+(?P<iface>\S+):\s+"
    r"(?P<src_ip>[\d.]+)\.(?P<src_port>\d+)\s*>\s*(?P<dst_ip>[\d.]+)\.(?P<dst_port>\d+)"
)


class FirewallLogParser(BaseLogParser):
    """Parser for firewall logs (iptables/UFW, PF-style)."""

    def can_parse(self, sample_lines: list[str]) -> float:
        fw_keywords = ["UFW", "BLOCK", "ALLOW", "DENY", "DROP", "ACCEPT", "REJECT",
                        "iptables", "SRC=", "DST=", "PROTO=", "DPT=", "SPT=",
                        "rule", "pass", "block"]
        hits = 0
        for line in sample_lines:
            if any(kw in line for kw in fw_keywords):
                hits += 1
        if not sample_lines:
            return 0.0
        return min(0.95, hits / len(sample_lines))

    def parse_line(self, line: str, line_number: int) -> Optional[ParsedLogEntry]:
        # Try PF-style
        pf_match = PF_PATTERN.search(line)
        if pf_match:
            return self._parse_pf(line, line_number, pf_match)

        # Try iptables-style
        ipt_match = IPTABLES_PATTERN.match(line)
        if ipt_match:
            return self._parse_iptables(line, line_number, ipt_match)

        # Fallback: try to extract key-value pairs
        kvs = dict(KV_PATTERN.findall(line))
        if kvs and ("SRC" in kvs or "DST" in kvs):
            return self._parse_kv(line, line_number, kvs)

        return ParsedLogEntry(
            line_number=line_number, raw_line=line,
            event_type="firewall_unparsed", message=line,
        )

    def _parse_iptables(self, line: str, line_number: int, match) -> ParsedLogEntry:
        timestamp_str = match.group("timestamp")
        try:
            ts = datetime.strptime(f"2026 {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = None

        message = match.group("message")
        kvs = dict(KV_PATTERN.findall(message))
        action = match.group("action") or kvs.get("ACTION", "unknown")

        event_type = "firewall_block" if "BLOCK" in action.upper() or "DROP" in action.upper() else "firewall_allow"

        try:
            dst_port = int(kvs.get("DPT", 0))
        except ValueError:
            dst_port = 0

        return ParsedLogEntry(
            line_number=line_number,
            timestamp=ts,
            source_ip=kvs.get("SRC"),
            destination_ip=kvs.get("DST"),
            event_type=event_type,
            message=f"{action} {kvs.get('PROTO', '')} {kvs.get('SRC', '')}:{kvs.get('SPT', '')} -> {kvs.get('DST', '')}:{kvs.get('DPT', '')}",
            raw_line=line,
            extra_fields={
                "action": action,
                "protocol": kvs.get("PROTO"),
                "source_port": kvs.get("SPT"),
                "destination_port": kvs.get("DPT"),
                "interface_in": kvs.get("IN"),
                "interface_out": kvs.get("OUT"),
                "hostname": match.group("hostname"),
            },
        )

    def _parse_pf(self, line: str, line_number: int, match) -> ParsedLogEntry:
        timestamp_str = match.group("timestamp")
        try:
            ts = datetime.strptime(f"2026 {timestamp_str}", "%Y %b %d %H:%M:%S")
        except ValueError:
            ts = None

        action = match.group("action")
        event_type = "firewall_block" if action == "block" else "firewall_allow"

        return ParsedLogEntry(
            line_number=line_number,
            timestamp=ts,
            source_ip=match.group("src_ip"),
            destination_ip=match.group("dst_ip"),
            event_type=event_type,
            message=f"{action} {match.group('direction')} {match.group('src_ip')}:{match.group('src_port')} -> {match.group('dst_ip')}:{match.group('dst_port')}",
            raw_line=line,
            extra_fields={
                "action": action,
                "direction": match.group("direction"),
                "interface": match.group("iface"),
                "source_port": match.group("src_port"),
                "destination_port": match.group("dst_port"),
            },
        )

    def _parse_kv(self, line: str, line_number: int, kvs: dict) -> ParsedLogEntry:
        action = kvs.get("ACTION", "unknown").upper()
        event_type = "firewall_block" if action in ("BLOCK", "DROP", "DENY", "REJECT") else "firewall_allow"

        return ParsedLogEntry(
            line_number=line_number,
            source_ip=kvs.get("SRC"),
            destination_ip=kvs.get("DST"),
            event_type=event_type,
            message=line[:500],
            raw_line=line,
            extra_fields=kvs,
        )
