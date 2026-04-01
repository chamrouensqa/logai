"""Aggregate IP reputation from AbuseIPDB and VirusTotal (optional API keys)."""

from __future__ import annotations

import ipaddress
import time
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import settings
from app.schemas.schemas import AbuseIpDbReputation, IpReputationResponse, VirusTotalReputation

CACHE_TTL_SEC = 3600
_cache: dict[str, tuple[float, IpReputationResponse]] = {}


def _normalize_ip(raw: str) -> str:
    addr = ipaddress.ip_address(raw.strip())
    if not addr.is_global:
        raise ValueError("Only public routable IP addresses can be checked (not private or reserved ranges).")
    return str(addr)


def _cache_get(key: str) -> IpReputationResponse | None:
    entry = _cache.get(key)
    if not entry:
        return None
    expires_at, payload = entry
    if time.time() > expires_at:
        del _cache[key]
        return None
    return payload


def _cache_set(key: str, payload: IpReputationResponse) -> None:
    _cache[key] = (time.time() + CACHE_TTL_SEC, payload)


async def _fetch_abuseipdb(client: httpx.AsyncClient, ip: str) -> tuple[AbuseIpDbReputation | None, str | None]:
    key = settings.ABUSEIPDB_API_KEY
    if not key:
        return None, None
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers={"Key": key, "Accept": "application/json"},
            timeout=20.0,
        )
        data = r.json()
        if r.status_code != 200:
            err = ""
            if isinstance(data.get("errors"), list) and data["errors"]:
                err = str(data["errors"][0].get("detail", r.text))
            else:
                err = r.text or f"HTTP {r.status_code}"
            return None, f"AbuseIPDB: {err}"
        d = data.get("data") or {}
        return (
            AbuseIpDbReputation(
                abuse_confidence_score=int(d.get("abuseConfidenceScore") or 0),
                total_reports=int(d.get("totalReports") or 0),
                country_code=d.get("countryCode"),
                isp=d.get("isp"),
                usage_type=d.get("usageType"),
                last_reported_at=d.get("lastReportedAt"),
                is_whitelisted=bool(d.get("isWhitelisted")),
                report_url=f"https://www.abuseipdb.com/check/{quote(ip, safe='')}",
            ),
            None,
        )
    except httpx.HTTPError as e:
        return None, f"AbuseIPDB: {e}"


async def _fetch_virustotal(client: httpx.AsyncClient, ip: str) -> tuple[VirusTotalReputation | None, str | None]:
    key = settings.VIRUSTOTAL_API_KEY
    if not key:
        return None, None
    path_ip = quote(ip, safe="")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{path_ip}"
    try:
        r = await client.get(
            url,
            headers={"x-apikey": key, "Accept": "application/json"},
            timeout=20.0,
        )
        data = r.json()
        if r.status_code == 404:
            stats = {"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0, "timeout": 0}
            rep = None
        elif r.status_code != 200:
            msg = data.get("error", {}).get("message") if isinstance(data.get("error"), dict) else r.text
            return None, f"VirusTotal: {msg or r.status_code}"
        else:
            attrs = (data.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            rep = attrs.get("reputation")
            if rep is not None:
                rep = int(rep)
            country = (attrs.get("country") or "") or None
            asn = attrs.get("as_owner") or attrs.get("network")
            if isinstance(asn, str):
                as_owner: str | None = asn
            else:
                as_owner = None
            return (
                VirusTotalReputation(
                    harmless=int(stats.get("harmless") or 0),
                    malicious=int(stats.get("malicious") or 0),
                    suspicious=int(stats.get("suspicious") or 0),
                    undetected=int(stats.get("undetected") or 0),
                    timeout=int(stats.get("timeout") or 0),
                    reputation=rep,
                    country=country,
                    as_owner=as_owner,
                    analysis_url=f"https://www.virustotal.com/gui/ip-address/{path_ip}",
                ),
                None,
            )
        return (
            VirusTotalReputation(
                harmless=int(stats.get("harmless") or 0),
                malicious=int(stats.get("malicious") or 0),
                suspicious=int(stats.get("suspicious") or 0),
                undetected=int(stats.get("undetected") or 0),
                timeout=int(stats.get("timeout") or 0),
                reputation=None,
                country=None,
                as_owner=None,
                analysis_url=f"https://www.virustotal.com/gui/ip-address/{path_ip}",
            ),
            None,
        )
    except httpx.HTTPError as e:
        return None, f"VirusTotal: {e}"


async def lookup_ip(raw_ip: str) -> IpReputationResponse:
    normalized = _normalize_ip(raw_ip)
    cached = _cache_get(normalized)
    if cached:
        out = cached.model_copy(update={"cached": True})
        return out

    cfg_ab = bool(settings.ABUSEIPDB_API_KEY)
    cfg_vt = bool(settings.VIRUSTOTAL_API_KEY)
    errors: list[str] = []

    if not cfg_ab and not cfg_vt:
        payload = IpReputationResponse(
            ip=normalized,
            cached=False,
            configured_abuseipdb=False,
            configured_virustotal=False,
            errors=[
                "No reputation API keys configured. Add ABUSEIPDB_API_KEY and/or VIRUSTOTAL_API_KEY to the backend .env."
            ],
        )
        return payload

    abuse: AbuseIpDbReputation | None = None
    vt: VirusTotalReputation | None = None

    async with httpx.AsyncClient() as client:
        if cfg_ab:
            abuse, err = await _fetch_abuseipdb(client, normalized)
            if err:
                errors.append(err)
        if cfg_vt:
            vt, err = await _fetch_virustotal(client, normalized)
            if err:
                errors.append(err)

    payload = IpReputationResponse(
        ip=normalized,
        cached=False,
        configured_abuseipdb=cfg_ab,
        configured_virustotal=cfg_vt,
        abuseipdb=abuse,
        virustotal=vt,
        errors=errors,
    )
    _cache_set(normalized, payload)
    return payload
