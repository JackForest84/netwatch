"""Detekce anomálií nad vlastní 14denní baseline (vlna 1: „appka přemýšlí").

Tři detektory, čistá SQL statistika (žádné ML závislosti), poctivé prahy:
hlásí se jen výrazné odchylky nad absolutním floorem, dedup 6 h přes tabulku
anomalies. Výsledky čte event feed + /api/anomalies + health banner.
"""
from __future__ import annotations

import logging
import statistics
import threading
import time

from store import store

log = logging.getLogger("netwatch.anomaly")

CHECK_S = 600            # kontrola každých 10 min
BASELINE_DAYS = 14
COOLDOWN_S = 6 * 3600    # stejná anomálie (kind+key) max 1× za 6 h


def _reported_recently(kind: str, key: str) -> bool:
    rows = store._query(
        "SELECT 1 FROM anomalies WHERE kind=? AND key=? AND ts > ? LIMIT 1",
        (kind, key, time.time() - COOLDOWN_S))
    return bool(rows)


def _insert(kind: str, key: str, severity: str, title: str, detail: str,
            value: float, baseline: float) -> None:
    store._exec(
        "INSERT INTO anomalies (ts, kind, key, severity, title, detail, value, baseline) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (time.time(), kind, key, severity, title, detail, value, baseline))
    log.info("anomálie [%s] %s — %s", kind, title, detail)


def _fmt_b(n: float) -> str:
    return f"{n / 1e9:.1f} GB" if n >= 1e9 else f"{n / 1e6:.0f} MB"


def check_device_traffic() -> None:
    """Zařízení, které za poslední hodinu výrazně překročilo svůj 14denní normál."""
    now = time.time()
    cur = {r["ip"]: (r["t"] or 0) for r in store._query(
        "SELECT ip, SUM(down_bytes + up_bytes) AS t FROM device_inet "
        "WHERE ts > ? GROUP BY ip", (now - 3600,))}
    if not cur:
        return
    base_rows = store._query(
        "SELECT ip, CAST(ts / 3600 AS INT) AS h, SUM(down_bytes + up_bytes) AS t "
        "FROM device_inet WHERE ts BETWEEN ? AND ? GROUP BY ip, h",
        (now - BASELINE_DAYS * 86400, now - 3600))
    base: dict[str, list[float]] = {}
    for r in base_rows:
        base.setdefault(r["ip"], []).append(r["t"] or 0)
    for ip, val in cur.items():
        hist = sorted(base.get(ip, []))
        # < 2 dny dat → normál neznáme, poctivě mlčíme (ADR 0003)
        if len(hist) < 48 or val < 300e6:
            continue
        p99 = hist[min(len(hist) - 1, int(len(hist) * 0.99))]
        if val > max(p99 * 1.5, 500e6):
            if _reported_recently("device-traffic", ip):
                continue
            import inventory
            name = inventory._NAME_OVERRIDES.get(ip) or ip
            _insert("device-traffic", ip, "warn",
                    f"Neobvyklý provoz: {name}",
                    f"{_fmt_b(val)} za poslední hodinu — normál (p99 za 14 dní) je {_fmt_b(p99)}",
                    val, p99)


def check_dns() -> None:
    """Skok v DNS dotazech proti stejné hodině dne za posledních 14 dní."""
    now = time.time()
    last_hour = int(now // 3600) * 3600 - 3600   # poslední UZAVŘENÁ hodina
    rows = store._query("SELECT SUM(queries) AS q FROM dns_history WHERE ts_hour = ?", (last_hour,))
    cur = (rows[0]["q"] or 0) if rows else 0
    if cur < 3000:
        return
    hod = time.localtime(last_hour).tm_hour
    hist = [r["q"] or 0 for r in store._query(
        "SELECT ts_hour, SUM(queries) AS q FROM dns_history "
        "WHERE ts_hour BETWEEN ? AND ? GROUP BY ts_hour",
        (now - BASELINE_DAYS * 86400, last_hour - 1))
        if time.localtime(r["ts_hour"]).tm_hour == hod]
    if len(hist) < 7:
        return
    mean = statistics.mean(hist)
    stdev = statistics.pstdev(hist) or 1.0
    if cur > mean + 3 * stdev and cur > 2 * mean:
        if _reported_recently("dns-spike", str(last_hour)):
            return
        _insert("dns-spike", str(last_hour), "warn",
                "Skok v DNS dotazech",
                f"{cur:,} dotazů v hodině {hod}:00 — normál je ~{int(mean):,} (±{int(stdev):,})".replace(",", " "),
                cur, mean)


def check_alerts() -> None:
    """Nárůst IDS alertů výrazně nad 14denní hodinový normál."""
    now = time.time()
    cur_rows = store._query("SELECT COUNT(*) AS n FROM alerts WHERE ts > ?", (now - 3600,))
    cur = cur_rows[0]["n"] if cur_rows else 0
    if cur < 200:
        return
    hist = [r["n"] for r in store._query(
        "SELECT CAST(ts / 3600 AS INT) AS h, COUNT(*) AS n FROM alerts "
        "WHERE ts BETWEEN ? AND ? GROUP BY h",
        (now - BASELINE_DAYS * 86400, now - 3600))]
    if len(hist) < 48:
        return
    mean = statistics.mean(hist)
    stdev = statistics.pstdev(hist) or 1.0
    if cur > mean + 4 * stdev and cur > 3 * mean:
        if _reported_recently("alert-spike", "global"):
            return
        _insert("alert-spike", "global", "warn",
                "Nárůst IDS alertů",
                f"{cur} alertů za poslední hodinu — normál je ~{int(mean)}/h. Mrkni na Bezpečnost.",
                cur, mean)


def _loop() -> None:
    time.sleep(90)
    while True:
        for check in (check_device_traffic, check_dns, check_alerts):
            try:
                check()
            except Exception:
                log.warning("anomaly check %s selhal", check.__name__, exc_info=True)
        time.sleep(CHECK_S)


def start_background() -> None:
    threading.Thread(target=_loop, daemon=True, name="anomaly").start()
