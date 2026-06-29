"""Alert aggregation over the SQLite store + ADR-0004 intent classification."""
from __future__ import annotations
import time
from collections import Counter
from threading import Lock
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Any

from store import store
from geoip import geo, country_to_flag

SEVERITY_LABEL = {1: "Kritická", 2: "Vážná", 3: "Méně vážná"}

# Intent classification (ADR 0004): group raw Suricata signatures by what they actually
# MEAN, instead of the generic ET classtype ("Misc Attack"). Lets the dashboard separate
# real attack attempts from high-volume threat-intel blocklist radiation.
INTENT_LABELS = {
    "attack":    "Pokusy o exploit/malware",
    "scan":      "Skeny portů",
    "blocklist": "Blocklist / reputace",
    "recon":     "Průzkum / info",
    "anomaly":   "Protokol / anomálie",
    "other":     "Ostatní",
}
INTENT_ACTIONABLE = {"attack", "scan"}  # the signal worth a human's attention


def classify_intent(signature: str | None, category: str | None = "") -> str:
    """Map a Suricata signature to an intent bucket key (see INTENT_LABELS)."""
    s = (signature or "").upper()
    if any(k in s for k in ("ET DROP", "DSHIELD", "SPAMHAUS", "CINS", "POOR REPUTATION",
                            "BLOCK LISTED", "BLOCKLISTED", "COMPROMISED", "ABUSE.CH", "KNOWN BAD")):
        return "blocklist"
    if any(k in s for k in ("SCAN", "SUSPICIOUS INBOUND", "NMAP", "PORTSCAN", "MASSCAN")):
        return "scan"
    if any(k in s for k in ("EXPLOIT", "ET WEB", "WEB_SPECIFIC", "WEB_SERVER", "ATTACK_RESPONSE",
                            "ET ATTACK", "SQL INJECT", "MALWARE", "TROJAN", "CURRENT_EVENTS",
                            "PHISHING", "ET MOBILE", "ET ADWARE")):
        return "attack"
    if any(k in s for k in ("DECODE", "STREAM", "CHECKSUM", "ICMP", "SURICATA", "PROTOCOL",
                            "ANOMALY", "BAD-TRAFFIC", "ET INFO")):
        return "anomaly"
    if "INFORMATION LEAK" in s or "RECON" in s or "ET POLICY" in s:
        return "recon"
    cu = (category or "").upper()
    if "MISC ATTACK" in cu:
        return "blocklist"
    if "BAD TRAFFIC" in cu or "POTENTIALLY BAD" in cu:
        return "anomaly"
    if "INFORMATION LEAK" in cu:
        return "recon"
    return "other"


# Short TTL cache: /api/overview + the Security tab call this every ~5 s with a small
# set of distinct `hours` values; the aggregation runs ~8 GROUP BY scans over the
# alerts table, so recomputing per request per viewer is the dashboard's hottest
# cost (audit perf). 20 s staleness is fine for a security summary.
_summary_cache: dict[float, tuple[float, dict]] = {}
_summary_cache_lock = Lock()
_SUMMARY_TTL = 20.0


def alert_summary_from_store(hours: float = 24) -> dict[str, Any]:
    now = time.time()
    with _summary_cache_lock:
        cached = _summary_cache.get(hours)
        if cached and now - cached[0] < _SUMMARY_TTL:
            return cached[1]
    result = _alert_summary_uncached(hours)
    with _summary_cache_lock:
        _summary_cache[hours] = (now, result)
    return result


def _alert_summary_uncached(hours: float = 24) -> dict[str, Any]:
    """Compute aggregates from SQLite (canonical) — survives eve.json rotation.

    `hours` is the window for donuts/countries/sources/intent headline so the
    Security tab can drive its own period selector (overview keeps the 24h
    default). The 24×1h timeline below is always the last 24h (overview-only)."""
    now_ts = time.time()
    cutoff_24h = now_ts - hours * 3600   # window (param); var name kept for git-blame stability
    cutoff_1h = now_ts - 3600
    now_local = datetime.now(ZoneInfo("Europe/Prague"))   # ne natvrdo +2 (rozbité v zimě)

    total_24h = store.alerts_count_period(hours)
    total_1h = store.alerts_count_period(1)

    # Timeline 24x1h
    buckets = [0] * 24
    bucket_labels: list[str] = []
    for i in range(24, 0, -1):
        slot_start = now_local - timedelta(hours=i)
        bucket_labels.append(slot_start.strftime("%H:00"))
    for row in store._query("SELECT ts FROM alerts WHERE ts > ?", (now_ts - 86400,)):
        h_ago = int((now_ts - row["ts"]) // 3600)
        if 0 <= h_ago < 24:
            buckets[23 - h_ago] += 1

    # Top signatures
    sig_rows = store._query(
        "SELECT signature, COUNT(*) AS hits FROM alerts WHERE ts > ? GROUP BY signature ORDER BY hits DESC LIMIT 10",
        (cutoff_24h,)
    )
    cat_rows = store._query(
        "SELECT category, COUNT(*) AS hits FROM alerts WHERE ts > ? GROUP BY category ORDER BY hits DESC LIMIT 8",
        (cutoff_24h,)
    )
    sev_rows = store._query(
        "SELECT severity, COUNT(*) AS hits FROM alerts WHERE ts > ? GROUP BY severity",
        (cutoff_24h,)
    )
    src_rows = store._query(
        "SELECT src_ip, COUNT(*) AS hits FROM alerts WHERE ts > ? AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY hits DESC LIMIT 10",
        (cutoff_24h,)
    )

    # Build top countries — and flag which attackers the firewall also dropped (ADR 0005)
    dropped_set = {r["src_ip"] for r in store._query(
        "SELECT DISTINCT src_ip FROM firewall_drops WHERE ts > ?", (cutoff_24h,)) if r["src_ip"]}
    country_counter: Counter = Counter()
    top_sources_full = []
    for r in src_rows:
        ip = r["src_ip"]; cnt = r["hits"]
        g = geo.lookup(ip)
        cc = g.get("country_code")
        if cc:
            country_counter[cc] += cnt
        top_sources_full.append({
            "ip": ip, "count": cnt,
            "country": g.get("country") or "—",
            "country_code": cc,
            "flag": country_to_flag(cc),
            "asn_org": (g.get("asn_org") or "—")[:40],
            "dropped": ip in dropped_set,
        })

    # Tally country across ALL alerts in 24h — single GROUP BY, geo.lookup once
    # per distinct IP (audit perf #10: was N+1, one COUNT query per IP).
    per_ip = store._query(
        "SELECT src_ip, COUNT(*) AS hits FROM alerts WHERE ts > ? AND src_ip IS NOT NULL GROUP BY src_ip",
        (cutoff_24h,)
    )
    country_counter = Counter()
    for r in per_ip:
        cc = geo.lookup(r["src_ip"]).get("country_code")
        if cc:
            country_counter[cc] += r["hits"]

    top_countries = [
        {"code": cc, "flag": country_to_flag(cc), "count": cnt}
        for cc, cnt in country_counter.most_common(10)
    ]

    severity_breakdown = {SEVERITY_LABEL.get(r["severity"], f"sev {r['severity']}"): r["hits"] for r in sev_rows if r["severity"] is not None}

    # Intent classification (ADR 0004): bucket signatures by what they MEAN, so real
    # attacks don't drown in high-volume threat-intel blocklist radiation.
    intent_rows = store._query(
        "SELECT signature, category, COUNT(*) AS hits FROM alerts WHERE ts > ? GROUP BY signature, category",
        (cutoff_24h,)
    )
    intent_counts: Counter = Counter()
    for r in intent_rows:
        intent_counts[classify_intent(r["signature"], r["category"])] += r["hits"]
    top_intents = [
        {"key": k, "label": INTENT_LABELS.get(k, k), "count": n}
        for k, n in intent_counts.most_common()
    ]
    intent_headline = {
        "actionable": sum(n for k, n in intent_counts.items() if k in INTENT_ACTIONABLE),
        "blocklist": intent_counts.get("blocklist", 0),
        "anomaly": intent_counts.get("anomaly", 0),
        "total": sum(intent_counts.values()),
    }

    return {
        "total_24h": total_24h,
        "total_1h": total_1h,
        "timeline": {"labels": bucket_labels, "values": buckets},
        "top_signatures": [{"signature": r["signature"] or "?", "count": r["hits"]} for r in sig_rows],
        "top_categories": [{"category": r["category"] or "?", "count": r["hits"]} for r in cat_rows],
        "top_intents": top_intents,
        "intent_headline": intent_headline,
        "top_sources": top_sources_full,
        "top_countries": top_countries,
        "severity": severity_breakdown,
    }


def recent_alerts_from_store(n: int = 25, hours: float | None = None) -> list[dict]:
    """Read recent alerts from SQLite for stable history. `hours` limits to a
    window (Security tab period filter); None = latest N regardless of age."""
    if hours:
        rows = store._query("SELECT * FROM alerts WHERE ts > ? ORDER BY ts DESC LIMIT ?",
                            (time.time() - hours * 3600, n))
    else:
        rows = store._query("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (n,))
    out: list[dict] = []
    for r in rows:
        ts = datetime.fromtimestamp(r["ts"])
        src = r.get("src_ip") or "?"
        g = geo.lookup(src)
        sev = r.get("severity") or 0
        _intent = classify_intent(r.get("signature"), r.get("category"))
        out.append({
            "time": ts.strftime("%H:%M:%S"),
            "date": ts.strftime("%Y-%m-%d"),
            "signature": r.get("signature") or "?",
            "severity": sev,
            "severity_label": SEVERITY_LABEL.get(sev, "?"),
            "intent": _intent,
            "intent_label": INTENT_LABELS.get(_intent, _intent),
            "category": r.get("category") or "?",
            "src": src,
            "src_port": r.get("src_port"),
            "dst": r.get("dst_ip") or "?",
            "dst_port": r.get("dst_port"),
            "proto": r.get("proto") or "?",
            "country": g.get("country") or "—",
            "country_code": g.get("country_code"),
            "flag": country_to_flag(g.get("country_code")),
            "asn_org": g.get("asn_org") or "—",
        })
    return out

def parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None
