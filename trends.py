"""Compute trend deltas (now vs last week) and 24h sparkline arrays."""

from __future__ import annotations

import time
from typing import Any

from threading import Lock

from store import store


def _delta(curr: float, prev: float) -> dict[str, Any]:
    if prev <= 0:
        return {"curr": curr, "prev": prev, "delta_pct": None, "direction": "flat"}
    pct = (curr - prev) * 100 / prev
    direction = "up" if pct > 5 else "down" if pct < -5 else "flat"
    return {"curr": curr, "prev": prev, "delta_pct": round(pct, 1), "direction": direction}


def alerts_trend() -> dict[str, Any]:
    now = time.time()
    cur = store._query("SELECT COUNT(*) AS n FROM alerts WHERE ts > ?", (now - 86400,))[0]["n"]
    prev = store._query("SELECT COUNT(*) AS n FROM alerts WHERE ts BETWEEN ? AND ?", (now - 14 * 86400, now - 7 * 86400))[0]["n"]
    return _delta(cur, prev)


def drops_trend() -> dict[str, Any]:
    now = time.time()
    cur = store._query("SELECT COUNT(*) AS n FROM firewall_drops WHERE ts > ?", (now - 86400,))[0]["n"]
    prev = store._query("SELECT COUNT(*) AS n FROM firewall_drops WHERE ts BETWEEN ? AND ?", (now - 14 * 86400, now - 7 * 86400))[0]["n"]
    return _delta(cur, prev)


def attackers_trend() -> dict[str, Any]:
    now = time.time()
    cur = store._query("SELECT COUNT(DISTINCT src_ip) AS n FROM firewall_drops WHERE ts > ?", (now - 86400,))[0]["n"]
    prev = store._query("SELECT COUNT(DISTINCT src_ip) AS n FROM firewall_drops WHERE ts BETWEEN ? AND ?", (now - 14 * 86400, now - 7 * 86400))[0]["n"]
    return _delta(cur, prev)


def devices_trend() -> dict[str, Any]:
    now = time.time()
    cur = store._query("SELECT COUNT(*) AS n FROM devices WHERE last_seen > ?", (now - 3600,))[0]["n"]
    prev = store._query("SELECT COUNT(*) AS n FROM devices WHERE last_seen BETWEEN ? AND ?", (now - 7 * 86400, now - 7 * 86400 + 3600))[0]["n"]
    return _delta(cur, prev)


def alerts_sparkline_24h() -> list[int]:
    now = time.time()
    buckets = [0] * 24
    rows = store._query(
        "SELECT ts FROM alerts WHERE ts > ?", (now - 86400,)
    )
    for r in rows:
        h_ago = int((now - r["ts"]) // 3600)
        if 0 <= h_ago < 24:
            buckets[23 - h_ago] += 1
    return buckets


def drops_sparkline_24h() -> list[int]:
    now = time.time()
    buckets = [0] * 24
    rows = store._query("SELECT ts FROM firewall_drops WHERE ts > ?", (now - 86400,))
    for r in rows:
        h_ago = int((now - r["ts"]) // 3600)
        if 0 <= h_ago < 24:
            buckets[23 - h_ago] += 1
    return buckets


def activity_heatmap_7d() -> dict[str, Any]:
    """Return 24x7 grid of alert+drop counts by hour-of-day x weekday."""
    now = time.time()
    cutoff = now - 7 * 86400
    grid = [[0] * 24 for _ in range(7)]  # weekday 0=Mon

    for row in store._query("SELECT ts FROM alerts WHERE ts > ?", (cutoff,)):
        t = time.localtime(row["ts"])
        grid[t.tm_wday][t.tm_hour] += 1
    for row in store._query("SELECT ts FROM firewall_drops WHERE ts > ?", (cutoff,)):
        t = time.localtime(row["ts"])
        grid[t.tm_wday][t.tm_hour] += 1

    max_v = max((max(r) for r in grid), default=0)
    return {"grid": grid, "max": max_v, "weekdays": ["Po", "Út", "St", "Čt", "Pá", "So", "Ne"]}


def attacker_geo_points(hours: int = 24, limit: int = 200) -> list[dict[str, Any]]:
    """Top attacker IPs with lat/lon for the globe.

    Combines IDS alerts + firewall drops. Uses GeoIP city DB (passed in)."""
    cutoff = time.time() - hours * 3600
    rows = store._query("""
        SELECT src_ip AS ip, COUNT(*) AS hits FROM (
            SELECT src_ip, ts FROM alerts WHERE ts > ? AND src_ip IS NOT NULL
            UNION ALL
            SELECT src_ip, ts FROM firewall_drops WHERE ts > ? AND src_ip IS NOT NULL
        )
        GROUP BY src_ip ORDER BY hits DESC LIMIT ?
    """, (cutoff, cutoff, limit))
    return rows


_trends_cache: tuple[float, dict] | None = None
_trends_lock = Lock()
_TRENDS_TTL = 60.0


def all_trends() -> dict[str, Any]:
    global _trends_cache
    now = time.time()
    with _trends_lock:
        if _trends_cache and now - _trends_cache[0] < _TRENDS_TTL:
            return _trends_cache[1]
    val = _all_trends_uncached()
    with _trends_lock:
        _trends_cache = (now, val)
    return val


def _all_trends_uncached() -> dict[str, Any]:
    return {
        "alerts": alerts_trend(),
        "drops": drops_trend(),
        "attackers": attackers_trend(),
        "devices_online": devices_trend(),
        "spark": {
            "alerts": alerts_sparkline_24h(),
            "drops": drops_sparkline_24h(),
        },
        "heatmap": activity_heatmap_7d(),
    }
