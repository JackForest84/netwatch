"""VirusTotal + AbuseIPDB enrichment with SQLite cache."""

from __future__ import annotations

import re
import time
from threading import Thread
from typing import Any

import requests

import config
from store import store

PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|169\.254\.)")


def _is_public(ip: str) -> bool:
    return bool(ip) and not PRIVATE.match(ip)


def _vt_lookup(ip: str, timeout: int = 8) -> dict | None:
    if not config.VIRUSTOTAL_API_KEY:
        return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
            timeout=timeout,
        )
        if r.status_code != 200:
            return None
        d = r.json().get("data", {}).get("attributes", {})
        stats = d.get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": d.get("country"),
            "as_owner": d.get("as_owner"),
            "asn": d.get("asn"),
            "reputation": d.get("reputation"),
            "last_analysis_date": d.get("last_analysis_date"),
        }
    except Exception:
        return None


def _abuse_lookup(ip: str, timeout: int = 8) -> dict | None:
    if not config.ABUSEIPDB_API_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=timeout,
        )
        if r.status_code != 200:
            return None
        d = r.json().get("data", {})
        return {
            "score": d.get("abuseConfidenceScore", 0),
            "reports": d.get("totalReports", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage": d.get("usageType"),
            "last_reported": d.get("lastReportedAt"),
        }
    except Exception:
        return None


def lookup(ip: str, force: bool = False) -> dict[str, Any]:
    """Return enrichment dict. Cached for ENRICH_TTL_HOURS."""
    if not _is_public(ip):
        return {"ip": ip, "private": True, "vt": None, "abuse": None}
    if not force:
        cached = store.get_enrichment(ip, config.ENRICH_TTL_HOURS)
        if cached:
            return {
                "ip": ip,
                "cached": True,
                "fetched_at": cached["fetched_at"],
                "vt": {
                    "malicious": cached["vt_malicious"],
                    "suspicious": cached["vt_suspicious"],
                    "country": cached["vt_country"],
                    "as_owner": cached["vt_as_owner"],
                } if cached.get("vt_malicious") is not None else None,
                "abuse": {
                    "score": cached["abuse_score"],
                    "reports": cached["abuse_reports"],
                    "country": cached["abuse_country"],
                    "isp": cached["abuse_isp"],
                } if cached.get("abuse_score") is not None else None,
            }
    vt = _vt_lookup(ip)
    abuse = _abuse_lookup(ip)
    if vt or abuse:
        store.upsert_enrichment(ip, vt, abuse)
    return {"ip": ip, "cached": False, "vt": vt, "abuse": abuse}


def background_enrich_top_attackers() -> None:
    """Background pass: keep enrichment fresh for top attacker IPs."""
    while True:
        try:
            top = store.top_attackers_period(hours=24, limit=20)
            for row in top:
                ip = row["src_ip"]
                if not _is_public(ip):
                    continue
                cached = store.get_enrichment(ip, config.ENRICH_TTL_HOURS)
                if cached:
                    continue
                lookup(ip)
                # VT free tier: 4/min. Sleep between calls.
                time.sleep(20)
        except Exception:
            pass
        time.sleep(config.ENRICH_INTERVAL_MIN * 60)


def start_background() -> None:
    Thread(target=background_enrich_top_attackers, daemon=True).start()
