"""SQLite persistence: rolling alert history, device first-seen ledger,
enrichment cache, firewall drops, notification dedup."""

from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, local
from typing import Any, Iterable

import config


def _bucket_start(ts: float, bucket_seconds: int) -> int:
    """Začátek bucketu. Pro denní (86400 s) zarovnává na LOKÁLNÍ půlnoc, ne UTC
    (jinak „den" v grafu běží 02:00–02:00, v zimě 01:00–01:00)."""
    if bucket_seconds == 86400:
        lt = time.localtime(ts)
        return int(time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)))
    return int(ts // bucket_seconds) * bucket_seconds


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,                -- unix epoch
    src_ip        TEXT,
    src_port      INTEGER,
    dst_ip        TEXT,
    dst_port      INTEGER,
    proto         TEXT,
    severity      INTEGER,
    signature     TEXT,
    signature_id  INTEGER,
    category      TEXT,
    country_code  TEXT,
    flow_id       INTEGER,
    raw_json      TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_sig ON alerts(signature_id);

CREATE TABLE IF NOT EXISTS devices (
    mac           TEXT PRIMARY KEY,
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    hostname      TEXT,
    ip            TEXT,
    vendor        TEXT,
    kind          TEXT,
    notes         TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS firewall_drops (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    chain         TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    proto         TEXT,
    iface_in      TEXT,
    iface_out     TEXT,
    country_code  TEXT,
    raw           TEXT
);
CREATE INDEX IF NOT EXISTS idx_drops_ts ON firewall_drops(ts);
CREATE INDEX IF NOT EXISTS idx_drops_src ON firewall_drops(src_ip);

CREATE TABLE IF NOT EXISTS enrichment (
    ip            TEXT PRIMARY KEY,
    fetched_at    REAL NOT NULL,
    vt_malicious  INTEGER,                       -- VT count of "malicious" engines
    vt_suspicious INTEGER,
    vt_country    TEXT,
    vt_as_owner   TEXT,
    vt_raw        TEXT,                          -- json blob
    abuse_score   INTEGER,                       -- 0-100
    abuse_reports INTEGER,
    abuse_country TEXT,
    abuse_isp     TEXT,
    abuse_raw     TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    kind          TEXT NOT NULL,                -- rule that fired
    key           TEXT NOT NULL,                -- per-rule dedup key
    payload       TEXT
);
CREATE INDEX IF NOT EXISTS idx_notif_kind_key_ts ON notifications(kind, key, ts);

CREATE TABLE IF NOT EXISTS traffic_snapshots (
    ts            REAL PRIMARY KEY,
    suri_pkts     INTEGER,
    suri_drops    INTEGER,
    mt_conn       INTEGER,
    mt_cpu_pct    INTEGER,
    eve_mb        REAL,
    devices_online INTEGER
);

CREATE TABLE IF NOT EXISTS device_traffic (
    ts            REAL NOT NULL,
    ip            TEXT NOT NULL,
    mac           TEXT,
    name          TEXT,
    tx_bytes      INTEGER NOT NULL,
    rx_bytes      INTEGER NOT NULL,
    PRIMARY KEY (ts, ip)
);
CREATE INDEX IF NOT EXISTS idx_dt_ip_ts ON device_traffic(ip, ts);

CREATE TABLE IF NOT EXISTS interface_traffic (
    ts            REAL NOT NULL,
    name          TEXT NOT NULL,
    category      TEXT NOT NULL,    -- wan | lan | vpn
    rx_bytes      INTEGER NOT NULL,
    tx_bytes      INTEGER NOT NULL,
    PRIMARY KEY (ts, name)
);
CREATE INDEX IF NOT EXISTS idx_it_cat_ts ON interface_traffic(category, ts);
CREATE INDEX IF NOT EXISTS idx_it_name_ts ON interface_traffic(name, ts);

-- REAL per-device internet bytes from the NetFlow v9 collector (delta per 60s flush)
CREATE TABLE IF NOT EXISTS device_inet (
    ts            REAL    NOT NULL,
    ip            TEXT    NOT NULL,
    down_bytes    INTEGER NOT NULL,
    up_bytes      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_di_ts ON device_inet(ts);

-- AdGuard DNS hourly history (ADR 0008). Sampled from /control/stats hourly
-- arrays via UPSERT: AdGuard only keeps the last 24 buckets, we keep the ones it
-- forgets, so the DNS/Security period filter can sum any window going forward.
CREATE TABLE IF NOT EXISTS dns_history (
    ts_hour       INTEGER NOT NULL,    -- unix epoch truncated to the hour
    instance      TEXT    NOT NULL,
    queries       INTEGER NOT NULL,
    blocked       INTEGER NOT NULL,
    PRIMARY KEY (ts_hour, instance)
);
CREATE INDEX IF NOT EXISTS idx_dnsh_ts ON dns_history(ts_hour);
CREATE INDEX IF NOT EXISTS idx_di_ip_ts ON device_inet(ip, ts);

-- Anomálie (vlna 1): baseline detektory zapisují, feed + API čtou
CREATE TABLE IF NOT EXISTS anomalies (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    kind          TEXT NOT NULL,      -- device-traffic | dns-spike | alert-spike
    key           TEXT NOT NULL,      -- ip / hodina / global
    severity      TEXT,
    title         TEXT,
    detail        TEXT,
    value         REAL,
    baseline      REAL
);
CREATE INDEX IF NOT EXISTS idx_anom_ts ON anomalies(ts);

-- Speedtest historie (vlna 3) — 4 řádky/den, neprunuje se
CREATE TABLE IF NOT EXISTS speedtest (
    ts            REAL PRIMARY KEY,
    down_mbps     REAL,
    up_mbps       REAL,
    latency_ms    REAL
);

-- Měsíční agregáty navždy (vlna 2) — přežijí 30denní retenci detailních tabulek
CREATE TABLE IF NOT EXISTS monthly_stats (
    month         TEXT NOT NULL,      -- YYYY-MM (localtime)
    metric        TEXT NOT NULL,
    value         REAL,
    PRIMARY KEY (month, metric)
);

-- Cache AI vysvětlení signatur (vlna 3) — signatury se opakují, volá se jednou
CREATE TABLE IF NOT EXISTS ai_explanations (
    signature     TEXT PRIMARY KEY,
    explanation   TEXT,
    model         TEXT,
    created_at    REAL
);

-- Covering indexes for hottest aggregations (audit perf #4)
CREATE INDEX IF NOT EXISTS idx_alerts_ts_src ON alerts(ts, src_ip);
CREATE INDEX IF NOT EXISTS idx_drops_ts_src ON firewall_drops(ts, src_ip);
"""


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = Lock()            # serializuje JEN zápisy na writer connection
        self._local = local()        # čtení: connection per vlákno (WAL → souběžní čtenáři)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.execute("PRAGMA cache_size=-32000;")        # 32 MB page cache (audit perf #3)
        self._conn.execute("PRAGMA wal_autocheckpoint=2000;")  # checkpoint sooner (audit perf #4)
        self._conn.execute("PRAGMA busy_timeout=5000;")        # wait up to 5s on a locked DB instead of raising (audit reliability)
        self._conn.executescript(SCHEMA)
        # Migrace: capacity sloupce v traffic_snapshots (audit: trend růstu dat)
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(traffic_snapshots)")}
        for col in ("db_mb", "wal_mb", "disk_pct", "health_score"):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE traffic_snapshots ADD COLUMN {col} REAL")

    def _exec(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        with self.lock:
            return self._conn.execute(sql, params)

    def _read_conn(self) -> sqlite3.Connection:
        """Read-only connection per vlákno. WAL dovolí libovolně mnoho souběžných
        čtenářů + 1 zapisovatele, takže UI čtení nikdy nečeká za background skenem
        ani zápisem (dřív vše serializoval jeden self.lock → kontence, audit)."""
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
            c.execute("PRAGMA query_only=ON;")
            c.execute("PRAGMA busy_timeout=5000;")
            self._local.conn = c
        return c

    def _query(self, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
        # BEZ self.lock — čte se z vláknové read connection, souběžně s kýmkoli jiným
        cur = self._read_conn().execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    # ---- Alerts -------------------------------------------------------------

    def latest_alert_ts(self) -> float:
        row = self._query("SELECT MAX(ts) AS m FROM alerts")
        return row[0]["m"] if row and row[0]["m"] else 0.0

    def insert_alerts(self, eve_events: Iterable[dict]) -> int:
        rows: list[tuple] = []
        for e in eve_events:
            if e.get("event_type") != "alert":
                continue
            try:
                ts = datetime.fromisoformat(e["timestamp"]).timestamp()
            except Exception:
                continue
            al = e.get("alert") or {}
            rows.append((
                ts,
                e.get("src_ip"), e.get("src_port"),
                e.get("dest_ip"), e.get("dest_port"),
                e.get("proto"),
                al.get("severity"),
                al.get("signature"), al.get("signature_id"),
                al.get("category"),
                None,           # country_code computed later
                e.get("flow_id"),
                json.dumps(e),
            ))
        if not rows:
            return 0
        with self.lock:
            self._conn.executemany(
                "INSERT INTO alerts (ts,src_ip,src_port,dst_ip,dst_port,proto,severity,signature,signature_id,category,country_code,flow_id,raw_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows
            )
        return len(rows)

    def prune_old_alerts(self) -> int:
        cutoff = time.time() - config.ALERT_RETENTION_DAYS * 86400
        cur = self._exec("DELETE FROM alerts WHERE ts < ?", (cutoff,))
        return cur.rowcount

    def top_attackers_period(self, hours: int = 24, limit: int = 10) -> list[dict]:
        cutoff = time.time() - hours * 3600
        return self._query(
            "SELECT src_ip, COUNT(*) AS hits, MAX(ts) AS last_ts, MIN(ts) AS first_ts "
            "FROM alerts WHERE ts > ? AND src_ip IS NOT NULL "
            "GROUP BY src_ip ORDER BY hits DESC LIMIT ?",
            (cutoff, limit)
        )

    def attacker_history(self, ip: str, days: int = 30) -> dict[str, Any]:
        cutoff = time.time() - days * 86400
        row = self._query(
            "SELECT COUNT(*) AS hits, MIN(ts) AS first_ts, MAX(ts) AS last_ts "
            "FROM alerts WHERE src_ip = ? AND ts > ?",
            (ip, cutoff)
        )
        return row[0] if row else {}

    # ---- Devices ledger -----------------------------------------------------

    def upsert_devices(self, devices: Iterable[dict]) -> tuple[int, list[dict]]:
        """Insert new devices and update last_seen. Returns (new_count, list_of_new)."""
        new_devs: list[dict] = []
        now = time.time()
        with self.lock:
            for d in devices:
                mac = (d.get("mac") or "").upper()
                if not mac:
                    continue
                cur = self._conn.execute(
                    "SELECT mac, first_seen FROM devices WHERE mac = ?", (mac,))
                existing = cur.fetchone()
                if existing:
                    self._conn.execute(
                        "UPDATE devices SET last_seen=?, hostname=COALESCE(NULLIF(?,''), hostname), "
                        "ip=COALESCE(?,ip), vendor=COALESCE(NULLIF(?,''), vendor), kind=COALESCE(?,kind) "
                        "WHERE mac=?",
                        (now, d.get("hostname"), d.get("ip"), d.get("vendor"), d.get("kind"), mac)
                    )
                else:
                    self._conn.execute(
                        "INSERT INTO devices (mac, first_seen, last_seen, hostname, ip, vendor, kind) "
                        "VALUES (?,?,?,?,?,?,?)",
                        (mac, now, now, d.get("hostname") or "", d.get("ip"), d.get("vendor") or "", d.get("kind"))
                    )
                    new_devs.append({**d, "mac": mac, "first_seen": now})
        return len(new_devs), new_devs

    def devices_first_seen_recently(self, minutes: int = 60) -> list[dict]:
        cutoff = time.time() - minutes * 60
        return self._query("SELECT * FROM devices WHERE first_seen > ? ORDER BY first_seen DESC", (cutoff,))

    def device_meta(self, mac: str) -> dict | None:
        rows = self._query("SELECT * FROM devices WHERE mac = ?", (mac.upper(),))
        return rows[0] if rows else None

    # ---- Firewall drops -----------------------------------------------------

    def insert_drops(self, drops: Iterable[dict]) -> int:
        rows = []
        for d in drops:
            rows.append((
                d.get("ts"), d.get("chain"),
                d.get("src_ip"), d.get("dst_ip"),
                d.get("src_port"), d.get("dst_port"),
                d.get("proto"), d.get("iface_in"), d.get("iface_out"),
                d.get("country_code"), d.get("raw"),
            ))
        if not rows:
            return 0
        with self.lock:
            self._conn.executemany(
                "INSERT INTO firewall_drops (ts,chain,src_ip,dst_ip,src_port,dst_port,proto,iface_in,iface_out,country_code,raw) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                rows
            )
        return len(rows)

    def top_drop_sources(self, hours: int = 24, limit: int = 10) -> list[dict]:
        cutoff = time.time() - hours * 3600
        return self._query(
            "SELECT src_ip, COUNT(*) AS hits FROM firewall_drops INDEXED BY idx_drops_ts WHERE ts > ? "
            "GROUP BY src_ip ORDER BY hits DESC LIMIT ?",
            (cutoff, limit)
        )

    def recent_drops(self, limit: int = 50) -> list[dict]:
        return self._query(
            "SELECT * FROM firewall_drops ORDER BY ts DESC LIMIT ?",
            (limit,)
        )

    def prune_old_drops(self) -> None:
        cutoff = time.time() - config.ALERT_RETENTION_DAYS * 86400
        self._exec("DELETE FROM firewall_drops WHERE ts < ?", (cutoff,))

    def prune_old_traffic(self) -> tuple[int, int]:
        """Prune device_traffic + interface_traffic past retention.

        Returns (device_rows_deleted, iface_rows_deleted)."""
        cutoff = time.time() - config.ALERT_RETENTION_DAYS * 86400
        c1 = self._exec("DELETE FROM device_traffic WHERE ts < ?", (cutoff,))
        c2 = self._exec("DELETE FROM interface_traffic WHERE ts < ?", (cutoff,))
        self._exec("DELETE FROM device_inet WHERE ts < ?", (cutoff,))
        self._exec("DELETE FROM dns_history WHERE ts_hour < ?", (cutoff,))
        return (c1.rowcount, c2.rowcount)

    def maintenance(self) -> dict:
        """Periodic housekeeping: prune everything past retention + incremental vacuum."""
        result = {
            "alerts": self.prune_old_alerts(),
            "drops": self._exec("DELETE FROM firewall_drops WHERE ts < ?",
                                (time.time() - config.ALERT_RETENTION_DAYS * 86400,)).rowcount,
        }
        dt, it = self.prune_old_traffic()
        result["device_traffic"] = dt
        result["interface_traffic"] = it
        # Snapshot pruning (keep 30d of system snapshots too)
        cutoff = time.time() - config.ALERT_RETENTION_DAYS * 86400
        result["snapshots"] = self._exec("DELETE FROM traffic_snapshots WHERE ts < ?", (cutoff,)).rowcount
        self._exec("DELETE FROM anomalies WHERE ts < ?", (time.time() - 90 * 86400,))
        try:
            self.update_monthly_stats()
        except Exception:
            pass
        # Incremental vacuum reclaims unused pages without locking
        with self.lock:
            self._conn.execute("PRAGMA incremental_vacuum(2000)")
            # Truncate WAL so it doesn't grow to 2x DB size (audit perf #4)
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("PRAGMA optimize")
        return result

    # ---- Enrichment cache ---------------------------------------------------

    def get_enrichment(self, ip: str, max_age_hours: int) -> dict | None:
        cutoff = time.time() - max_age_hours * 3600
        rows = self._query("SELECT * FROM enrichment WHERE ip = ? AND fetched_at > ?", (ip, cutoff))
        return rows[0] if rows else None

    def upsert_enrichment(self, ip: str, vt: dict | None, abuse: dict | None) -> None:
        now = time.time()
        with self.lock:
            self._conn.execute(
                "INSERT INTO enrichment (ip, fetched_at, vt_malicious, vt_suspicious, vt_country, vt_as_owner, vt_raw, abuse_score, abuse_reports, abuse_country, abuse_isp, abuse_raw) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET fetched_at=excluded.fetched_at, "
                "vt_malicious=COALESCE(excluded.vt_malicious, vt_malicious), "
                "vt_suspicious=COALESCE(excluded.vt_suspicious, vt_suspicious), "
                "vt_country=COALESCE(excluded.vt_country, vt_country), "
                "vt_as_owner=COALESCE(excluded.vt_as_owner, vt_as_owner), "
                "vt_raw=COALESCE(excluded.vt_raw, vt_raw), "
                "abuse_score=COALESCE(excluded.abuse_score, abuse_score), "
                "abuse_reports=COALESCE(excluded.abuse_reports, abuse_reports), "
                "abuse_country=COALESCE(excluded.abuse_country, abuse_country), "
                "abuse_isp=COALESCE(excluded.abuse_isp, abuse_isp), "
                "abuse_raw=COALESCE(excluded.abuse_raw, abuse_raw)",
                (
                    ip, now,
                    (vt or {}).get("malicious"), (vt or {}).get("suspicious"),
                    (vt or {}).get("country"), (vt or {}).get("as_owner"),
                    json.dumps(vt) if vt is not None else None,
                    (abuse or {}).get("score"), (abuse or {}).get("reports"),
                    (abuse or {}).get("country"), (abuse or {}).get("isp"),
                    json.dumps(abuse) if abuse is not None else None,
                )
            )

    # ---- Notification dedup -------------------------------------------------

    def notify_was_recent(self, kind: str, key: str, cooldown_min: int) -> bool:
        cutoff = time.time() - cooldown_min * 60
        rows = self._query(
            "SELECT 1 FROM notifications WHERE kind=? AND key=? AND ts > ? LIMIT 1",
            (kind, key, cutoff)
        )
        return bool(rows)

    def notify_record(self, kind: str, key: str, payload: dict) -> None:
        self._exec(
            "INSERT INTO notifications (ts, kind, key, payload) VALUES (?,?,?,?)",
            (time.time(), kind, key, json.dumps(payload))
        )

    # ---- Traffic snapshots --------------------------------------------------

    def insert_snapshot(self, snap: dict) -> None:
        self._exec(
            "INSERT OR REPLACE INTO traffic_snapshots (ts, suri_pkts, suri_drops, mt_conn, mt_cpu_pct, eve_mb, devices_online, db_mb, wal_mb, disk_pct, health_score) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), snap.get("suri_pkts"), snap.get("suri_drops"), snap.get("mt_conn"),
             snap.get("mt_cpu_pct"), snap.get("eve_mb"), snap.get("devices_online"),
             snap.get("db_mb"), snap.get("wal_mb"), snap.get("disk_pct"), snap.get("health_score"))
        )

    def recent_anomalies(self, hours: float = 24) -> list[dict]:
        return self._query(
            "SELECT * FROM anomalies WHERE ts > ? ORDER BY ts DESC LIMIT 50",
            (time.time() - hours * 3600,))

    def speedtest_history(self, days: int = 7) -> list[dict]:
        return self._query(
            "SELECT ts, down_mbps, up_mbps, latency_ms FROM speedtest WHERE ts > ? ORDER BY ts",
            (time.time() - days * 86400,))

    def update_monthly_stats(self) -> None:
        """Upsert agregátů AKTUÁLNÍHO měsíce (volá maintenance à 1 h). MAX guard:
        čítače v měsíci jen rostou, takže když detailní data odtečou retencí
        (31denní měsíc vs 30denní retence), nepodlezeme dřívější hodnotu."""
        lt = time.localtime()
        ym = time.strftime("%Y-%m", lt)
        m0 = time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1))

        def scalar(q: str, *p) -> float:
            rows = self._query(q, p)
            return (rows[0]["n"] or 0) if rows else 0

        wan = self.interface_traffic_month("wan", ym)
        vals = {
            "alerts": scalar("SELECT COUNT(*) AS n FROM alerts WHERE ts >= ?", m0),
            "fw_drops": scalar("SELECT COUNT(*) AS n FROM firewall_drops WHERE ts >= ?", m0),
            "attackers": scalar(
                "SELECT COUNT(*) AS n FROM (SELECT src_ip FROM alerts WHERE ts >= ? AND src_ip IS NOT NULL "
                "UNION SELECT src_ip FROM firewall_drops WHERE ts >= ? AND src_ip IS NOT NULL)", m0, m0),
            "dns_queries": scalar("SELECT SUM(queries) AS n FROM dns_history WHERE ts_hour >= ?", m0),
            "dns_blocked": scalar("SELECT SUM(blocked) AS n FROM dns_history WHERE ts_hour >= ?", m0),
            "wan_down_gb": round((wan.get("rx_bytes") or 0) / 1e9, 2),
            "wan_up_gb": round((wan.get("tx_bytes") or 0) / 1e9, 2),
            "anomalies": scalar("SELECT COUNT(*) AS n FROM anomalies WHERE ts >= ?", m0),
        }
        with self.lock:
            self._conn.executemany(
                "INSERT INTO monthly_stats (month, metric, value) VALUES (?,?,?) "
                "ON CONFLICT(month, metric) DO UPDATE SET value=MAX(value, excluded.value)",
                [(ym, k, v) for k, v in vals.items()])

    def monthly_stats(self) -> list[dict]:
        """[{month, alerts, fw_drops, ...}] — řádek per měsíc, nejnovější první."""
        rows = self._query("SELECT month, metric, value FROM monthly_stats ORDER BY month DESC")
        out: dict[str, dict] = {}
        for r in rows:
            out.setdefault(r["month"], {"month": r["month"]})[r["metric"]] = r["value"]
        return list(out.values())

    def capacity_history(self, days: int = 30) -> list[dict]:
        """Poslední snapshot za každý (lokální) den — trend růstu dat (audit)."""
        cutoff = time.time() - days * 86400
        rows = self._query(
            "SELECT ts, eve_mb, db_mb, wal_mb, disk_pct FROM traffic_snapshots WHERE ts > ? ORDER BY ts",
            (cutoff,))
        daily: dict[int, dict] = {}
        for r in rows:
            daily[_bucket_start(r["ts"], 86400)] = r
        return [{"ts": ts, "eve_mb": r["eve_mb"], "db_mb": r["db_mb"],
                 "wal_mb": r["wal_mb"], "disk_pct": r["disk_pct"]}
                for ts, r in sorted(daily.items())]

    # ---- Stats over rolling window -----------------------------------------

    def alerts_count_period(self, hours: int) -> int:
        cutoff = time.time() - hours * 3600
        rows = self._query("SELECT COUNT(*) AS n FROM alerts WHERE ts > ?", (cutoff,))
        return rows[0]["n"] if rows else 0

    # ---- Per-device traffic snapshots --------------------------------------

    def insert_device_traffic(self, samples: list[dict]) -> None:
        if not samples:
            return
        now = time.time()
        rows = []
        for s in samples:
            ip = s.get("ip")
            if not ip:
                continue
            rows.append((now, ip, (s.get("mac") or "").upper() or None,
                         s.get("name") or s.get("hostname"),
                         int(s.get("tx_bytes") or 0), int(s.get("rx_bytes") or 0)))
        if rows:
            with self.lock:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO device_traffic (ts, ip, mac, name, tx_bytes, rx_bytes) VALUES (?,?,?,?,?,?)",
                    rows
                )

    def monthly_device_traffic(self, year_month: str | None = None) -> list[dict]:
        ym = year_month or time.strftime("%Y-%m", time.localtime())
        rows = self._query("""
            SELECT ip, mac, name, ts, tx_bytes, rx_bytes
            FROM device_traffic
            WHERE strftime('%Y-%m', ts, 'unixepoch') = ?
            ORDER BY ip, ts
        """, (ym,))
        if not rows:
            return []
        by_ip: dict[str, dict] = {}
        prev: dict[str, dict] = {}
        for r in rows:
            ip = r["ip"]
            agg = by_ip.setdefault(ip, {
                "ip": ip, "mac": r["mac"], "name": r["name"],
                "tx_bytes": 0, "rx_bytes": 0, "samples": 0,
                "first_ts": r["ts"], "last_ts": r["ts"],
            })
            p = prev.get(ip)
            if p:
                dx = r["tx_bytes"] - p["tx_bytes"]
                dr = r["rx_bytes"] - p["rx_bytes"]
                if dx > 0: agg["tx_bytes"] += dx
                if dr > 0: agg["rx_bytes"] += dr
            agg["samples"] += 1
            agg["last_ts"] = r["ts"]
            if r["name"]: agg["name"] = r["name"]
            if r["mac"]: agg["mac"] = r["mac"]
            prev[ip] = r
        out = list(by_ip.values())
        for d in out:
            d["total_bytes"] = d["tx_bytes"] + d["rx_bytes"]
        out.sort(key=lambda x: x["total_bytes"], reverse=True)
        return out

    def daily_traffic_buckets(self, days: int = 7) -> list[dict]:
        """Total daily WAN traffic across all devices (sum of positive deltas)."""
        cutoff = time.time() - days * 86400
        rows = self._query(
            "SELECT ts, ip, tx_bytes, rx_bytes FROM device_traffic WHERE ts > ? ORDER BY ip, ts",
            (cutoff,)
        )
        from collections import defaultdict
        buckets: dict[str, dict] = defaultdict(lambda: {"tx": 0, "rx": 0})
        prev: dict[str, dict] = {}
        for r in rows:
            day = time.strftime("%Y-%m-%d", time.localtime(r["ts"]))
            p = prev.get(r["ip"])
            if p:
                dx = r["tx_bytes"] - p["tx_bytes"]
                dr = r["rx_bytes"] - p["rx_bytes"]
                if dx > 0: buckets[day]["tx"] += dx
                if dr > 0: buckets[day]["rx"] += dr
            prev[r["ip"]] = r
        return [{"day": d, **b} for d, b in sorted(buckets.items())]

    # ---- Per-interface (WAN/LAN/VPN) snapshots + time-range queries --------

    def insert_interface_traffic(self, samples: list[dict]) -> None:
        """Records (ts, name, category, rx, tx) per interface; idempotent on PK."""
        if not samples:
            return
        now = time.time()
        rows = []
        for s in samples:
            name = s.get("name")
            if not name:
                continue
            rows.append((
                now, name, s.get("category", "lan"),
                int(s.get("rx_bytes") or 0),
                int(s.get("tx_bytes") or 0),
            ))
        if rows:
            with self.lock:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO interface_traffic (ts, name, category, rx_bytes, tx_bytes) VALUES (?,?,?,?,?)",
                    rows
                )

    def interface_traffic_period(self, category: str, period_hours: float) -> dict:
        """Sum positive deltas of all interfaces in category over the past N hours."""
        cutoff = time.time() - period_hours * 3600
        rows = self._query("""
            SELECT ts, name, rx_bytes, tx_bytes FROM interface_traffic
            WHERE category = ? AND ts > ?
            ORDER BY name, ts
        """, (category, cutoff))
        total_rx = total_tx = 0
        ifaces: dict[str, dict] = {}
        prev: dict[str, dict] = {}
        for r in rows:
            name = r["name"]
            agg = ifaces.setdefault(name, {"name": name, "rx_bytes": 0, "tx_bytes": 0})
            p = prev.get(name)
            if p:
                dr = r["rx_bytes"] - p["rx_bytes"]
                dx = r["tx_bytes"] - p["tx_bytes"]
                if dr > 0:
                    agg["rx_bytes"] += dr; total_rx += dr
                if dx > 0:
                    agg["tx_bytes"] += dx; total_tx += dx
            prev[name] = r
        return {
            "rx_bytes": total_rx,
            "tx_bytes": total_tx,
            "interfaces": list(ifaces.values()),
        }

    def interface_traffic_history(self, category: str, period_hours: float, bucket_seconds: int) -> list[dict]:
        """Bucketed time-series: list of {ts_bucket, rx, tx} for the category."""
        cutoff = time.time() - period_hours * 3600
        rows = self._query("""
            SELECT ts, name, rx_bytes, tx_bytes FROM interface_traffic
            WHERE category = ? AND ts > ?
            ORDER BY name, ts
        """, (category, cutoff))
        from collections import defaultdict
        buckets: dict[int, dict] = defaultdict(lambda: {"rx": 0, "tx": 0})
        prev: dict[str, dict] = {}
        for r in rows:
            bucket = _bucket_start(r["ts"], bucket_seconds)
            p = prev.get(r["name"])
            if p:
                dr = r["rx_bytes"] - p["rx_bytes"]
                dx = r["tx_bytes"] - p["tx_bytes"]
                if dr > 0: buckets[bucket]["rx"] += dr
                if dx > 0: buckets[bucket]["tx"] += dx
            prev[r["name"]] = r
        return [{"ts": ts, **b} for ts, b in sorted(buckets.items())]

    def interface_traffic_month(self, category: str, year_month: str | None = None) -> dict:
        """Sum positive deltas of rx/tx for a category within a calendar month (local time).

        year_month = 'YYYY-MM' (default current month). Used for 'this month / last
        month' internet (WAN) and VPN totals. WAN=ether5 and VPN=wg are single
        interfaces, so there is no double-counting here (unlike the LAN bridge)."""
        ym = year_month or time.strftime("%Y-%m", time.localtime())
        rows = self._query("""
            SELECT ts, name, rx_bytes, tx_bytes FROM interface_traffic
            WHERE category = ? AND strftime('%Y-%m', ts, 'unixepoch', 'localtime') = ?
            ORDER BY name, ts
        """, (category, ym))
        total_rx = total_tx = 0
        prev: dict[str, dict] = {}
        for r in rows:
            p = prev.get(r["name"])
            if p:
                dr = r["rx_bytes"] - p["rx_bytes"]
                dx = r["tx_bytes"] - p["tx_bytes"]
                if dr > 0: total_rx += dr
                if dx > 0: total_tx += dx
            prev[r["name"]] = r
        return {"rx_bytes": total_rx, "tx_bytes": total_tx, "year_month": ym}

    # ---- AdGuard DNS hourly history (ADR 0008) -----------------------------

    def insert_dns_buckets(self, rows: list) -> None:
        """rows = [(ts_hour, instance, queries, blocked), ...]. Idempotent UPSERT:
        re-sampling the same hour just refreshes its (still-growing) counts."""
        if not rows:
            return
        with self.lock:
            self._conn.executemany(
                "INSERT INTO dns_history (ts_hour, instance, queries, blocked) VALUES (?,?,?,?) "
                "ON CONFLICT(ts_hour, instance) DO UPDATE SET "
                "queries=MAX(queries, excluded.queries), blocked=MAX(blocked, excluded.blocked)",
                rows,
            )

    def dns_history_period(self, period_hours: float) -> dict:
        """Sum queries/blocked across all instances over the past N hours, plus the
        oldest bucket we actually have (so the UI can flag 'historie od …')."""
        cutoff = time.time() - period_hours * 3600
        rows = self._query(
            "SELECT COALESCE(SUM(queries),0) AS q, COALESCE(SUM(blocked),0) AS b, "
            "MIN(ts_hour) AS since FROM dns_history WHERE ts_hour > ?",
            (cutoff,),
        )
        r = rows[0] if rows else {"q": 0, "b": 0, "since": None}
        q, b = r["q"] or 0, r["b"] or 0
        return {
            "queries": q,
            "blocked": b,
            "block_rate_pct": round(b * 100 / q, 1) if q else 0,
            "since": r["since"],
        }

    def dns_history_buckets(self, period_hours: float, bucket_seconds: int) -> list[dict]:
        """Bucketed time-series [{ts, queries, blocked}] for the DNS history chart."""
        cutoff = time.time() - period_hours * 3600
        rows = self._query(
            "SELECT ts_hour, SUM(queries) AS q, SUM(blocked) AS b FROM dns_history "
            "WHERE ts_hour > ? GROUP BY ts_hour ORDER BY ts_hour",
            (cutoff,),
        )
        from collections import defaultdict
        buckets: dict[int, dict] = defaultdict(lambda: {"queries": 0, "blocked": 0})
        for r in rows:
            bk = _bucket_start(r["ts_hour"], bucket_seconds)
            buckets[bk]["queries"] += r["q"] or 0
            buckets[bk]["blocked"] += r["b"] or 0
        return [{"ts": ts, **b} for ts, b in sorted(buckets.items())]

    def insert_device_inet(self, rows: list) -> None:
        """rows = [(ip, down_bytes, up_bytes), ...] — delta since last NetFlow flush."""
        if not rows:
            return
        now = time.time()
        data = [(now, ip, int(d or 0), int(u or 0)) for ip, d, u in rows]
        with self.lock:
            self._conn.executemany(
                "INSERT INTO device_inet (ts, ip, down_bytes, up_bytes) VALUES (?,?,?,?)", data)

    def device_inet_history(self, ip: str, hours: float, bucket_seconds: int) -> list[dict]:
        """Bucketovaná časová řada down/up pro jedno zařízení (audit UX: per-device graf)."""
        cutoff = time.time() - hours * 3600
        rows = self._query(
            "SELECT ts, down_bytes, up_bytes FROM device_inet WHERE ip = ? AND ts > ? ORDER BY ts",
            (ip, cutoff))
        from collections import defaultdict
        buckets: dict[int, dict] = defaultdict(lambda: {"down": 0, "up": 0})
        for r in rows:
            bk = _bucket_start(r["ts"], bucket_seconds)
            buckets[bk]["down"] += r["down_bytes"] or 0
            buckets[bk]["up"] += r["up_bytes"] or 0
        return [{"ts": ts, **b} for ts, b in sorted(buckets.items())]

    def device_inet_period(self, hours: float = 24) -> list[dict]:
        cutoff = time.time() - hours * 3600
        rows = self._query(
            "SELECT ip, SUM(down_bytes) AS d, SUM(up_bytes) AS u FROM device_inet "
            "WHERE ts > ? GROUP BY ip", (cutoff,))
        out = [{"ip": r["ip"], "down_bytes": r["d"] or 0, "up_bytes": r["u"] or 0,
                "total_bytes": (r["d"] or 0) + (r["u"] or 0)} for r in rows]
        out.sort(key=lambda x: x["total_bytes"], reverse=True)
        return out


store = Store(config.STORE_DB_PATH)
