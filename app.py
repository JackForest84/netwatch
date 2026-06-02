"""Admin dashboard for the mikrotiktraffic IDS server.

Reads live data from:
  - systemd (service status, uptime)
  - psutil (CPU, RAM, disk, network)
  - /var/log/suricata/eve.json (alerts)
  - /var/lib/GeoIP/*.mmdb (country/ASN lookup)
  - redis-cli info (Redis stats)
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import subprocess
import time
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, Thread
from typing import Any

import base64
import maxminddb
import psutil
import secrets as _secrets
from urllib.parse import parse_qs, quote
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.middleware.base import BaseHTTPMiddleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("netwatch")

import config
import adguard_client
import enrich
import firewall_log
import inventory
import mikrotik_client
import notify
import ntopng_client
import traffic_tracker
import netflow_collector
import firewall_syslog
import trends
import unifi_client
import unifi_legacy
from store import store

GEOIP_CITY = Path("/var/lib/GeoIP/GeoLite2-City.mmdb")

BASE = Path(__file__).parent
EVE_PATH = Path("/var/log/suricata/eve.json")
GEOIP_COUNTRY = Path("/var/lib/GeoIP/GeoLite2-Country.mmdb")
GEOIP_ASN = Path("/var/lib/GeoIP/GeoLite2-ASN.mmdb")

SERVICES = [
    ("suricata-wan", "Suricata", "Sleduje provoz tvé sítě a poznává útoky podle 47 000 pravidel (port skeny, brute-force, exploity, botnety, malware komunikace). Když najde podezřelý paket, vytvoří alert."),
    ("ntopng-wan", "ntopng", "Analyzátor síťových toků. Umí říct kdo s kým mluví, kolik bytů, jakou aplikaci a kde sedí v Internetu (ASN, country). Druhotná databáze: Redis."),
    ("evebox-local", "EveBox", "Webová appka pro listování v alertech Suricaty. Vidíš v ní historii, filtruješ podle IP/signatury/země. UI na portu 5636."),
    ("tzsp-replay", "TZSP replay", "MikroTik zrcadlí WAN traffic přes TZSP protokol do téhle aplikace. tzsp-replay ho rozbalí a pošle na rozhraní dummy0, kde si ho Suricata + ntopng vyzvedávají."),
    ("redis-server", "Redis", "In-memory databáze pro ntopng. Drží statistiky, deduplikační hashe, krátkodobou historii toků. 512MB max, LRU policy."),
    ("geoipupdate.timer", "GeoIP update", "Týdně stahuje aktuální databázi GeoIP2 od MaxMind. Díky tomu vidíš u každé IP zemi + ASN."),
    ("admin-dashboard", "NetWatch UI", "Tahle webová aplikace. FastAPI + SQLite, agreguje data z Suricaty, MikroTiku, UniFi, AdGuardu a posílá push notifikace."),
    ("ntfy", "ntfy", "Push notifikační server. Když se něco vážného stane, dostaneš zprávu do mobilu (self-hosted, žádný cloud)."),
]

NTOPNG_PORT = 3000
EVEBOX_PORT = 5636

app = FastAPI(title="NetWatch")


# Security headers added to every response (audit security: no HSTS/CSP/X-Frame).
# CSP allows the CDNs the dashboard genuinely loads (tailwind, chart.js, d3, fonts) +
# inline styles/scripts (the app is a single self-contained template).
_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none'; base-uri 'self'"
    ),
}


# Form-based login with a signed session cookie. Replaces the old HTTP Basic Auth
# (a browser popup) so password managers like Proton Pass can autofill it and offer
# to save it. Keeps the per-IP brute-force lockout and the security headers.
_session_serializer = URLSafeTimedSerializer(config.SESSION_SECRET, salt="netwatch-auth")


def _apply_security_headers(resp):
    for k, v in _SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


class AuthGuard:
    """Shared auth state: per-IP brute-force lockout + session token sign/verify."""

    MAX_FAILS = 10           # lockout threshold
    LOCKOUT_SECONDS = 300    # 5 min lockout
    WINDOW_SECONDS = 300     # failures counted within this rolling window

    def __init__(self):
        self._fails: dict[str, list[float]] = {}      # ip -> [fail_ts, ...]
        self._locked: dict[str, float] = {}           # ip -> locked_until_ts
        self._lock = Lock()

    def client_ip(self, request) -> str:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
        return request.client.host if request.client else "?"

    def is_locked(self, ip: str) -> bool:
        with self._lock:
            until = self._locked.get(ip)
            if until and time.time() < until:
                return True
            if until:
                del self._locked[ip]
            return False

    def record_fail(self, ip: str) -> None:
        now = time.time()
        with self._lock:
            fails = [t for t in self._fails.get(ip, []) if now - t < self.WINDOW_SECONDS]
            fails.append(now)
            self._fails[ip] = fails
            if len(fails) >= self.MAX_FAILS:
                self._locked[ip] = now + self.LOCKOUT_SECONDS
                self._fails[ip] = []
                log.warning("auth lockout: %s locked for %ds after %d fails", ip, self.LOCKOUT_SECONDS, self.MAX_FAILS)

    def record_ok(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)

    def check_credentials(self, user: str, pwd: str) -> bool:
        if not config.DASHBOARD_PASS:
            return False
        return (_secrets.compare_digest(user, config.DASHBOARD_USER)
                and _secrets.compare_digest(pwd, config.DASHBOARD_PASS))

    def make_token(self, user: str) -> str:
        return _session_serializer.dumps({"u": user})

    def valid_session(self, token) -> bool:
        if not token:
            return False
        try:
            data = _session_serializer.loads(token, max_age=config.SESSION_TTL_DAYS * 86400)
        except (BadSignature, SignatureExpired):
            return False
        except Exception:
            return False
        return bool(data) and _secrets.compare_digest(str(data.get("u", "")), config.DASHBOARD_USER)


auth = AuthGuard()


class AuthMiddleware(BaseHTTPMiddleware):
    """Require a valid session cookie; redirect to /login otherwise. Adds security headers."""

    @staticmethod
    def _is_public(path: str) -> bool:
        return path in ("/login", "/logout", "/favicon.ico") or path.startswith("/static/")

    async def dispatch(self, request, call_next):
        if config.DASHBOARD_PASS and not self._is_public(request.url.path):
            if not auth.valid_session(request.cookies.get(config.SESSION_COOKIE)):
                if request.url.path.startswith("/api/"):
                    return _apply_security_headers(
                        JSONResponse({"error": "unauthorized"}, status_code=401))
                target = request.url.path
                if request.url.query:
                    target = target + "?" + request.url.query
                return _apply_security_headers(
                    RedirectResponse("/login?next=" + quote(target, safe=""), status_code=303))
        resp = await call_next(request)
        return _apply_security_headers(resp)


app.add_middleware(AuthMiddleware)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE / "templates"))


# ---------------------------------------------------------------------------
# eve.json tail cache — keeps an in-memory rolling window of recent events
# ---------------------------------------------------------------------------

class EveTail:
    """Background thread that tails eve.json and keeps recent events in memory.

    Keeps alerts in a separate, larger deque so KPIs over 24h don't lose them
    when high-volume flow/stats events push them out of the general buffer.
    """

    def __init__(self, path: Path, max_events: int = 2000, max_alerts: int = 2000) -> None:
        self.path = path
        self.events: deque[dict] = deque(maxlen=max_events)
        self.alerts: deque[dict] = deque(maxlen=max_alerts)
        self.lock = Lock()
        self.inode = None
        self.pos = 0
        self._stop = False
        self.thread = Thread(target=self._run, daemon=True)
        self.thread.start()

    def _seed_from_tail(self) -> None:
        """Read last 2 MB so the live tail is warm; SQLite holds the 30d history."""
        try:
            size = self.path.stat().st_size
            with self.path.open("rb") as f:
                start = max(0, size - 2 * 1024 * 1024)
                f.seek(start)
                if start > 0:
                    f.readline()  # discard partial line
                for raw in f:
                    self._ingest(raw)
                self.pos = f.tell()
                self.inode = self.path.stat().st_ino
        except FileNotFoundError:
            pass

    def _ingest(self, raw: bytes) -> None:
        try:
            ev = json.loads(raw)
        except Exception:
            return
        with self.lock:
            self.events.append(ev)
            if ev.get("event_type") == "alert":
                self.alerts.append(ev)

    def _run(self) -> None:
        self._seed_from_tail()
        while not self._stop:
            try:
                st = self.path.stat()
            except FileNotFoundError:
                time.sleep(2)
                continue
            if self.inode is None or st.st_ino != self.inode or st.st_size < self.pos:
                self.inode = st.st_ino
                self.pos = 0
            if st.st_size > self.pos:
                try:
                    with self.path.open("rb") as f:
                        f.seek(self.pos)
                        for raw in f:
                            if raw.endswith(b"\n"):
                                self._ingest(raw)
                                self.pos = f.tell()
                            else:
                                break
                except Exception:
                    pass
            time.sleep(1)

    def snapshot(self) -> list[dict]:
        with self.lock:
            return list(self.events)

    def snapshot_alerts(self) -> list[dict]:
        with self.lock:
            return list(self.alerts)


eve_tail = EveTail(EVE_PATH)


# ---------------------------------------------------------------------------
# Background persistence threads — alerts + devices + traffic snapshots
# ---------------------------------------------------------------------------

def _persist_loop() -> None:
    """Persist new alerts to SQLite, plus device first-seen ledger."""
    import time as _t
    _t.sleep(10)
    last_seen_ts = store.latest_alert_ts()
    while True:
        try:
            alerts = eve_tail.snapshot_alerts()
            new = []
            for e in alerts:
                try:
                    ts = datetime.fromisoformat(e["timestamp"]).timestamp()
                except Exception:
                    continue
                if ts > last_seen_ts:
                    new.append(e)
            if new:
                store.insert_alerts(new)
                last_seen_ts = max(
                    datetime.fromisoformat(e["timestamp"]).timestamp() for e in new
                )
            # Hourly maintenance: prune ALL tables past retention + incremental vacuum
            if int(_t.time()) % 3600 < 30:
                try:
                    store.maintenance()
                except Exception:
                    log.warning("maintenance failed", exc_info=True)
        except Exception:
            log.warning("persist loop iteration failed", exc_info=True)
        _t.sleep(30)


def _devices_persist_loop() -> None:
    import time as _t
    _t.sleep(20)
    while True:
        try:
            mt = mikrotik_client.client.get() if mikrotik_client.client else {}
            un = unifi_client.client.get() if unifi_client.client else {}
            devs = inventory.build(mt, un) if (mt or un) else []
            online = [d for d in devs if d.get("online")]
            new_count, _ = store.upsert_devices(online)
            # snapshot
            store.insert_snapshot({
                "suri_pkts": 0,
                "suri_drops": 0,
                "mt_conn": mt.get("connections_count", 0) if mt else 0,
                "mt_cpu_pct": int((mt.get("resource") or {}).get("cpu-load", 0)) if mt else 0,
                "eve_mb": EVE_PATH.stat().st_size / 1024 / 1024 if EVE_PATH.exists() else 0,
                "devices_online": len(online),
            })
        except Exception:
            log.warning("devices persist loop iteration failed", exc_info=True)
        _t.sleep(60)


def _dns_history_sampler() -> None:
    """Fold AdGuard's hourly stats arrays into dns_history (ADR 0008). AdGuard
    serves only the last 24 hourly buckets; we UPSERT them every few minutes and
    keep the ones it later drops, so the DNS/Security period filter can sum any
    window going forward. No extra HTTP — reuses the adguard_client poll cache."""
    import time as _t
    _t.sleep(25)
    while True:
        try:
            if adguard_client.client:
                hour_now = int(_t.time() // 3600) * 3600
                rows: list[tuple] = []
                for s in adguard_client.client.get_all():
                    stats = s.get("stats") or {}
                    q = stats.get("dns_queries") or []
                    b = stats.get("blocked_filtering") or []
                    n = len(q)
                    for i in range(n):
                        ts_hour = hour_now - (n - 1 - i) * 3600
                        rows.append((
                            ts_hour, s.get("name") or "?",
                            int(q[i] or 0),
                            int(b[i] or 0) if i < len(b) else 0,
                        ))
                store.insert_dns_buckets(rows)
        except Exception:
            log.warning("dns history sampler iteration failed", exc_info=True)
        _t.sleep(300)


Thread(target=_persist_loop, daemon=True).start()
Thread(target=_devices_persist_loop, daemon=True).start()
enrich.start_background()
firewall_log.start_background()
notify.start_background()
traffic_tracker.start_background()
netflow_collector.start_background()
firewall_syslog.start_background()
Thread(target=_dns_history_sampler, daemon=True).start()


# ---------------------------------------------------------------------------
# GeoIP lookup
# ---------------------------------------------------------------------------

PRIVATE_NETS = (
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"^127\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^fe80:"),
    re.compile(r"^::1$"),
)


def _is_private(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_NETS)


class GeoLookup:
    def __init__(self) -> None:
        self.country = self._open(GEOIP_COUNTRY)
        self.city = self._open(GEOIP_CITY)
        self.asn = self._open(GEOIP_ASN)

    def _open(self, path: Path):
        try:
            return maxminddb.open_database(str(path))
        except FileNotFoundError:
            return None

    def lookup(self, ip: str) -> dict[str, Any]:
        out: dict[str, Any] = {"country": None, "country_code": None, "asn": None, "asn_org": None,
                                "lat": None, "lon": None, "city": None}
        if not ip or _is_private(ip):
            return out
        if self.country:
            try:
                r = self.country.get(ip)
                if r and "country" in r:
                    out["country"] = r["country"]["names"].get("en")
                    out["country_code"] = r["country"]["iso_code"]
            except Exception:
                pass
        if self.city:
            try:
                r = self.city.get(ip)
                if r:
                    loc = r.get("location") or {}
                    out["lat"] = loc.get("latitude")
                    out["lon"] = loc.get("longitude")
                    city = (r.get("city") or {}).get("names", {})
                    out["city"] = city.get("en")
                    if not out.get("country"):
                        out["country"] = (r.get("country") or {}).get("names", {}).get("en")
                        out["country_code"] = (r.get("country") or {}).get("iso_code")
            except Exception:
                pass
        if self.asn:
            try:
                r = self.asn.get(ip)
                if r:
                    out["asn"] = r.get("autonomous_system_number")
                    out["asn_org"] = r.get("autonomous_system_organization")
            except Exception:
                pass
        return out


def country_to_flag(code: str | None) -> str:
    if not code or len(code) != 2:
        return "🌐"
    return chr(0x1F1E6 + ord(code[0].upper()) - ord("A")) + chr(0x1F1E6 + ord(code[1].upper()) - ord("A"))


geo = GeoLookup()


# ---------------------------------------------------------------------------
# Service status
# ---------------------------------------------------------------------------

def _systemctl(*args: str) -> str:
    try:
        return subprocess.check_output(
            ["systemctl", *args], text=True, stderr=subprocess.DEVNULL, timeout=3
        ).strip()
    except Exception:
        return ""


# 10 s TTL cache for service_status — avoids 48 systemctl shell-outs per refresh
# (audit perf #1: was ~570 ms / 5 s budget, ~22 % of single-worker event loop).
_svc_cache: dict[str, tuple[float, dict]] = {}
_svc_cache_lock = Lock()
_SVC_TTL = 10.0


def service_status(unit: str) -> dict[str, Any]:
    now = time.time()
    with _svc_cache_lock:
        cached = _svc_cache.get(unit)
        if cached and now - cached[0] < _SVC_TTL:
            return cached[1]
    info = _service_status_uncached(unit)
    with _svc_cache_lock:
        _svc_cache[unit] = (now, info)
    return info


def _service_status_uncached(unit: str) -> dict[str, Any]:
    active = _systemctl("is-active", unit) or "unknown"
    enabled = _systemctl("is-enabled", unit) or "unknown"
    info: dict[str, Any] = {
        "unit": unit, "active": active, "enabled": enabled,
        "since": None, "pid": None, "mem_mb": None, "cpu_pct": None,
        "uptime_str": None,
    }
    if active == "active":
        show = _systemctl("show", unit, "--property=ActiveEnterTimestamp,MainPID,MemoryCurrent")
        for line in show.splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k == "ActiveEnterTimestamp" and v:
                info["since"] = v
                try:
                    started = datetime.strptime(v, "%a %Y-%m-%d %H:%M:%S %Z").timestamp()
                    info["uptime_str"] = uptime_string(time.time() - started)
                except Exception:
                    pass
            elif k == "MainPID" and v.isdigit() and int(v) > 0:
                info["pid"] = int(v)
            elif k == "MemoryCurrent" and v.isdigit():
                info["mem_mb"] = round(int(v) / (1024 * 1024), 1)
        if info["pid"]:
            try:
                p = psutil.Process(info["pid"])
                info["cpu_pct"] = round(p.cpu_percent(interval=0.05), 1)
            except Exception:
                pass
    return info


def uptime_string(secs: float) -> str:
    secs = int(secs)
    d, secs = divmod(secs, 86400)
    h, secs = divmod(secs, 3600)
    m = secs // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# ---------------------------------------------------------------------------
# Network deltas — sampled in background
# ---------------------------------------------------------------------------

class NetSampler:
    def __init__(self, interfaces: list[str]) -> None:
        self.interfaces = interfaces
        self.samples: dict[str, dict] = {}
        self.lock = Lock()
        Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        prev = psutil.net_io_counters(pernic=True)
        prev_ts = time.time()
        while True:
            time.sleep(2)
            now = psutil.net_io_counters(pernic=True)
            now_ts = time.time()
            dt = now_ts - prev_ts or 1
            with self.lock:
                for iface in self.interfaces:
                    if iface not in now or iface not in prev:
                        continue
                    a, b = prev[iface], now[iface]
                    self.samples[iface] = {
                        "rx_bps": (b.bytes_recv - a.bytes_recv) * 8 / dt,
                        "tx_bps": (b.bytes_sent - a.bytes_sent) * 8 / dt,
                        "rx_pps": (b.packets_recv - a.packets_recv) / dt,
                        "tx_pps": (b.packets_sent - a.packets_sent) / dt,
                        "rx_total": b.bytes_recv,
                        "tx_total": b.bytes_sent,
                    }
            prev = now
            prev_ts = now_ts

    def get(self, iface: str) -> dict:
        with self.lock:
            return dict(self.samples.get(iface, {}))


net_sampler = NetSampler(["ens18", "dummy0"])


# ---------------------------------------------------------------------------
# Suricata-specific
# ---------------------------------------------------------------------------

def suricata_socket_stat() -> dict[str, Any]:
    try:
        raw = subprocess.check_output(
            ["suricatasc", "-c", "iface-stat dummy0"], text=True, timeout=2
        )
        m = json.loads(raw)
        return m.get("message", {}) if m.get("return") == "OK" else {}
    except Exception:
        return {}


def disk_usage_dir(path: str) -> int:
    try:
        out = subprocess.check_output(["du", "-sb", path], text=True, timeout=3, stderr=subprocess.DEVNULL)
        return int(out.split()[0])
    except Exception:
        return 0


def redis_info() -> dict[str, str]:
    try:
        out = subprocess.check_output(["redis-cli", "info"], text=True, timeout=2)
        d: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line and not line.startswith("#"):
                k, v = line.split(":", 1)
                d[k.strip()] = v.strip()
        return d
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Aggregations over recent alerts
# ---------------------------------------------------------------------------

def parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


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


def alert_summary_from_store(hours: float = 24) -> dict[str, Any]:
    """Compute aggregates from SQLite (canonical) — survives eve.json rotation.

    `hours` is the window for donuts/countries/sources/intent headline so the
    Security tab can drive its own period selector (overview keeps the 24h
    default). The 24×1h timeline below is always the last 24h (overview-only)."""
    now_ts = time.time()
    cutoff_24h = now_ts - hours * 3600   # window (param); var name kept for git-blame stability
    cutoff_1h = now_ts - 3600
    now_local = datetime.now(timezone(timedelta(hours=2)))

    total_24h = store.alerts_count_period(hours)
    total_1h = store.alerts_count_period(1)

    # Timeline 24x1h
    buckets = [0] * 24
    bucket_labels: list[str] = []
    for i in range(24, 0, -1):
        slot_start = now_local - timedelta(hours=i)
        bucket_labels.append(slot_start.strftime("%H:00"))
    for row in store._query("SELECT ts FROM alerts WHERE ts > ?", (cutoff_24h,)):
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _get_server_ip() -> str:
    for iface, addrs in psutil.net_if_addrs().items():
        if iface in ("lo", "dummy0"):
            continue
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                return a.address
    return "127.0.0.1"


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {
        "request": request,
        "hostname": socket.gethostname(),
        "app_name": config.APP_NAME,
        "app_tagline": config.APP_TAGLINE,
        "ntopng_port": NTOPNG_PORT,
        "evebox_port": EVEBOX_PORT,
        "server_ip": _get_server_ip(),
    })


def _safe_next(nxt) -> str:
    if isinstance(nxt, str) and nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return "/"


def _login_page(request: Request, *, next: str = "/", error: str = "", status: int = 200) -> HTMLResponse:
    resp = templates.TemplateResponse("login.html", {
        "request": request,
        "app_name": config.APP_NAME,
        "app_tagline": config.APP_TAGLINE,
        "next": next,
        "error": error,
    }, status_code=status)
    return _apply_security_headers(resp)


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    if auth.valid_session(request.cookies.get(config.SESSION_COOKIE)):
        return _apply_security_headers(RedirectResponse("/", status_code=303))
    return _login_page(request, next=_safe_next(request.query_params.get("next", "/")))


@app.post("/login")
async def login_post(request: Request):
    ip = auth.client_ip(request)
    raw = await request.body()
    form = parse_qs(raw.decode("utf-8", "ignore"))
    user = (form.get("username") or [""])[0]
    pwd = (form.get("password") or [""])[0]
    nxt = _safe_next((form.get("next") or ["/"])[0])

    if auth.is_locked(ip):
        return _login_page(request, next=nxt,
                           error="Příliš mnoho pokusů. Zkuste to znovu za pár minut.",
                           status=429)
    if auth.check_credentials(user, pwd):
        auth.record_ok(ip)
        resp = RedirectResponse(nxt or "/", status_code=303)
        resp.set_cookie(config.SESSION_COOKIE, auth.make_token(user),
                        max_age=config.SESSION_TTL_DAYS * 86400,
                        httponly=True, secure=True, samesite="lax", path="/")
        return _apply_security_headers(resp)
    auth.record_fail(ip)
    log.warning("failed login from %s (user=%r)", ip, user[:32])
    return _login_page(request, next=nxt, error="Nesprávné jméno nebo heslo.", status=401)


@app.get("/logout")
def logout(request: Request):
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(config.SESSION_COOKIE, path="/")
    return _apply_security_headers(resp)


@app.get("/api/overview")
def api_overview() -> JSONResponse:
    boot = psutil.boot_time()
    load1, load5, load15 = os.getloadavg()
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk_root = psutil.disk_usage("/")

    svc_data = []
    for unit, label, desc in SERVICES:
        s = service_status(unit)
        svc_data.append({**s, "label": label, "description": desc})

    iface_dummy0 = net_sampler.get("dummy0")
    iface_ens18 = net_sampler.get("ens18")
    suri_iface = suricata_socket_stat()
    rinfo = redis_info()

    eve_size = 0
    try:
        eve_size = EVE_PATH.stat().st_size
    except FileNotFoundError:
        pass
    suri_log_size = disk_usage_dir("/var/log/suricata")

    events = eve_tail.snapshot()
    # Use SQLite (canonical, survives eve.json rotation)
    summary = alert_summary_from_store()

    return JSONResponse({
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "uptime": uptime_string(time.time() - boot),
        "boot_time": datetime.fromtimestamp(boot).strftime("%Y-%m-%d %H:%M"),
        "load": {"1": round(load1, 2), "5": round(load5, 2), "15": round(load15, 2)},
        "cpu_count": psutil.cpu_count(),
        "cpu_pct": round(psutil.cpu_percent(interval=0.0), 1),
        "mem": {
            "total_mb": round(mem.total / 1024 / 1024, 0),
            "used_mb": round(mem.used / 1024 / 1024, 0),
            "pct": mem.percent,
        },
        "swap": {
            "total_mb": round(swap.total / 1024 / 1024, 0),
            "used_mb": round(swap.used / 1024 / 1024, 0),
            "pct": swap.percent,
        },
        "disk": {
            "total_gb": round(disk_root.total / 1024**3, 1),
            "used_gb": round(disk_root.used / 1024**3, 1),
            "pct": disk_root.percent,
        },
        "services": svc_data,
        "network": {
            "ens18": iface_ens18,
            "dummy0": iface_dummy0,
        },
        "suricata": {
            "iface_pkts": suri_iface.get("pkts", 0),
            "iface_drops": suri_iface.get("drop", 0),
            "iface_invalid_chksum": suri_iface.get("invalid-checksums", 0),
        },
        "redis": {
            "used_mb": round(float(rinfo.get("used_memory", 0)) / 1024 / 1024, 1) if rinfo.get("used_memory") else 0,
            "maxmemory_mb": round(float(rinfo.get("maxmemory", 0)) / 1024 / 1024, 0) if rinfo.get("maxmemory") else 0,
            "policy": rinfo.get("maxmemory_policy", "?"),
            "keys": int(rinfo.get("db0", "keys=0").split(",")[0].replace("keys=", "")) if rinfo.get("db0") else 0,
            "version": rinfo.get("redis_version", "?"),
        },
        "logs": {
            "eve_mb": round(eve_size / 1024 / 1024, 1),
            "suricata_total_mb": round(suri_log_size / 1024 / 1024, 1),
            "events_cached": len(events),
        },
        "alerts": summary,
    })


@app.get("/api/recent-alerts")
def api_recent_alerts(n: int = 25, hours: float | None = None) -> JSONResponse:
    # SQLite-backed = robust against eve.json rotation
    return JSONResponse({"alerts": recent_alerts_from_store(n=n, hours=hours)})


@app.get("/api/security-summary")
def api_security_summary(hours: float = 24) -> JSONResponse:
    """Alert aggregates (intents, severity, countries, sources, headline) for an
    arbitrary window — powers the Security tab's own period selector. Same JSON
    shape as the overview's `alerts` block, so the same renderer consumes both."""
    return JSONResponse(alert_summary_from_store(hours=hours))


@app.get("/api/network")
def api_network() -> JSONResponse:
    """Inventory + MikroTik + UniFi snapshot."""
    mt = mikrotik_client.client.get() if mikrotik_client.client else {"last_error": "no creds"}
    un = unifi_client.client.get() if unifi_client.client else {"last_error": "no creds"}

    devs = inventory.build(mt, un) if (mt and un) else []
    summary = inventory.summarize(devs) if devs else {}

    # MikroTik interface bandwidth (current totals; UI computes deltas)
    iface_summary = []
    for i in mt.get("interfaces", []):
        if i.get("type") in ("loopback",):
            continue
        iface_summary.append({
            "name": i.get("name"),
            "type": i.get("type"),
            "running": i.get("running"),
            "rx_byte": i.get("rx_byte"),
            "tx_byte": i.get("tx_byte"),
            "comment": i.get("comment"),
        })

    # Per-AP client count + per-switch
    ap_clients: dict[str, int] = {}
    for c in un.get("clients", []):
        uid = c.get("uplink_device_id")
        if uid:
            ap_clients[uid] = ap_clients.get(uid, 0) + 1

    infra = []
    for d in un.get("devices", []):
        infra.append({
            "id": d.get("id"),
            "name": d.get("name"),
            "model": d.get("model"),
            "mac": d.get("mac"),
            "ip": d.get("ip"),
            "state": d.get("state"),
            "version": d.get("version"),
            "uptime": d.get("uptime"),
            "client_count": ap_clients.get(d.get("id"), 0),
        })

    # MikroTik system resource
    res = mt.get("resource", {})
    mt_summary = {
        "version": res.get("version"),
        "board": res.get("board-name"),
        "uptime": res.get("uptime"),
        "cpu_load_pct": int(res.get("cpu-load", 0)) if res.get("cpu-load") else 0,
        "free_memory_mb": round(int(res.get("free-memory", 0)) / 1024 / 1024, 0) if res.get("free-memory") else 0,
        "total_memory_mb": round(int(res.get("total-memory", 0)) / 1024 / 1024, 0) if res.get("total-memory") else 0,
        "free_hdd_mb": round(int(res.get("free-hdd-space", 0)) / 1024 / 1024, 1) if res.get("free-hdd-space") else 0,
        "total_hdd_mb": round(int(res.get("total-hdd-space", 0)) / 1024 / 1024, 1) if res.get("total-hdd-space") else 0,
        "connections_active": mt.get("connections_count", 0),
        "wireguard_peers_total": len(mt.get("wireguard_peers", [])),
        "wireguard_peers_active": len([p for p in mt.get("wireguard_peers", []) if p.get("last_handshake")]),
        "last_error": mt.get("last_error"),
        "last_fetch": mt.get("last_fetch"),
    }

    unifi_summary = {
        "version": un.get("info", {}).get("applicationVersion"),
        "last_error": un.get("last_error"),
        "last_fetch": un.get("last_fetch"),
    }

    # Compact device list for UI
    devices = []
    for d in devs:
        last_seen = d.get("last_seen")
        devices.append({
            "mac": d.get("mac"),
            "ip": d.get("ip"),
            "hostname": d.get("hostname"),
            "vendor": d.get("vendor") or "",
            "kind": d.get("kind"),
            "client_type": d.get("client_type"),
            "online": d.get("online", False),
            "uplink": d.get("uplink_name"),
            "uplink_model": d.get("uplink_model"),
            "infra_model": d.get("infra_model"),
            "infra_state": d.get("infra_state"),
            "last_seen": last_seen,
            "lease_status": d.get("lease_status"),
            "source": d.get("source", []),
        })

    return JSONResponse({
        "summary": summary,
        "devices": devices,
        "infra": infra,
        "interfaces": iface_summary,
        "wireguard": mt.get("wireguard_peers", []),
        "mikrotik": mt_summary,
        "unifi": unifi_summary,
    })


@app.get("/api/wifi")
def api_wifi() -> JSONResponse:
    """Per-AP client detail from UniFi legacy API: signal, retries, DPI."""
    legacy = unifi_legacy.client.get() if unifi_legacy.client else {"clients": [], "last_error": "legacy creds missing"}
    integration = unifi_client.client.get() if unifi_client.client else {"devices": []}

    devices_by_mac = {d.get("mac"): d for d in integration.get("devices", []) if d.get("mac")}

    # Group clients by AP
    per_ap: dict[str, dict] = {}
    for c in legacy.get("clients", []):
        if c.get("is_wired"):
            continue
        ap_mac = c.get("ap_mac") or "?"
        ap_info = devices_by_mac.get(ap_mac, {})
        ap_key = ap_mac
        if ap_key not in per_ap:
            per_ap[ap_key] = {
                "ap_name": ap_info.get("name") or ap_mac,
                "ap_model": ap_info.get("model"),
                "ap_mac": ap_mac,
                "clients": [],
            }
        per_ap[ap_key]["clients"].append({
            "mac": c.get("mac"),
            "hostname": c.get("hostname") or c.get("mac"),
            "ip": c.get("ip"),
            "radio": c.get("radio_proto") or c.get("radio"),
            "channel": c.get("channel"),
            "signal": c.get("signal"),
            "rssi": c.get("rssi"),
            "tx_rate_kbps": c.get("tx_rate_kbps"),
            "rx_rate_kbps": c.get("rx_rate_kbps"),
            "tx_retries": c.get("tx_retries"),
            "essid": c.get("essid"),
            "uptime": c.get("uptime"),
            "tx_bytes": c.get("tx_bytes"),
            "rx_bytes": c.get("rx_bytes"),
        })

    # Sort clients in each AP by signal desc
    for ap in per_ap.values():
        ap["clients"].sort(key=lambda x: (x.get("signal") or -200), reverse=True)
        ap["client_count"] = len(ap["clients"])
        signals = [c["signal"] for c in ap["clients"] if c["signal"] is not None]
        ap["avg_signal"] = round(sum(signals) / len(signals)) if signals else None

    # Wired clients summary (per switch)
    wired = [c for c in legacy.get("clients", []) if c.get("is_wired")]
    per_switch: dict[str, dict] = {}
    for c in wired:
        sw_mac = c.get("sw_mac") or "?"
        sw_info = devices_by_mac.get(sw_mac, {})
        if sw_mac not in per_switch:
            per_switch[sw_mac] = {
                "sw_name": sw_info.get("name") or sw_mac,
                "sw_model": sw_info.get("model"),
                "sw_mac": sw_mac,
                "clients": [],
            }
        per_switch[sw_mac]["clients"].append({
            "mac": c.get("mac"),
            "hostname": c.get("hostname") or c.get("mac"),
            "ip": c.get("ip"),
            "port": c.get("sw_port"),
            "tx_bytes": c.get("tx_bytes"),
            "rx_bytes": c.get("rx_bytes"),
        })
    for sw in per_switch.values():
        sw["clients"].sort(key=lambda x: x.get("port") or 999)
        sw["client_count"] = len(sw["clients"])

    return JSONResponse({
        "aps": list(per_ap.values()),
        "switches": list(per_switch.values()),
        "events_recent": legacy.get("events", [])[:30],
        "rogue_aps": legacy.get("rogue_aps", [])[:20],
        "last_error": legacy.get("last_error"),
        "last_fetch": legacy.get("last_fetch"),
    })


@app.get("/api/firewall")
def api_firewall(hours: int = 24) -> JSONResponse:
    top = store.top_drop_sources(hours=hours, limit=15)
    recent = store.recent_drops(limit=50)
    # Enrich top with geo
    for row in top:
        ip = row["src_ip"]
        if ip:
            g = geo.lookup(ip)
            row["country"] = g["country"]
            row["country_code"] = g["country_code"]
            row["flag"] = country_to_flag(g["country_code"])
            en = store.get_enrichment(ip, max_age_hours=72)
            if en:
                row["abuse_score"] = en.get("abuse_score")
                row["vt_malicious"] = en.get("vt_malicious")
    return JSONResponse({
        "top": top,
        "recent": recent,
        "total_24h": sum(r["hits"] for r in top),
    })


@app.get("/api/outcome")
def api_outcome(hours: int = 24) -> JSONResponse:
    """The 'so what' view (ADR 0005): correlate IDS detections (who knocked) with the
    firewall verdict (did the door hold) + the actually exposed surface. Inbound WAN
    scans are dropped at the perimeter; this proves it instead of implying impact."""
    cut = time.time() - hours * 3600

    def scalar(q: str, *a) -> int:
        rows = store._query(q, a)
        return rows[0]["n"] if rows else 0

    ids_alerts = scalar("SELECT COUNT(*) AS n FROM alerts WHERE ts > ?", cut)
    ids_attackers = scalar("SELECT COUNT(DISTINCT src_ip) AS n FROM alerts WHERE ts > ? AND src_ip IS NOT NULL", cut)
    fw_drops = scalar("SELECT COUNT(*) AS n FROM firewall_drops WHERE ts > ?", cut)
    # Match attackers (in window) against a WIDER drop lookback (≥24h): Suricata's
    # mirror-fed alert and the firewall's drop for the same IP rarely land in the same
    # instant, so a same-window intersection under-counts (the IP is dropped, just not
    # in that exact hour). The question is "is this attacker on our drop record", not
    # "was this exact packet dropped this hour". Proven: unmatched-in-1h IPs are all
    # present in 24h drops.
    drop_cut = time.time() - max(hours, 24) * 3600
    attackers_dropped = scalar(
        "SELECT COUNT(DISTINCT src_ip) AS n FROM alerts WHERE ts > ? AND src_ip IN "
        "(SELECT src_ip FROM firewall_drops WHERE ts > ?)", cut, drop_cut)
    blocked_ports = store._query(
        "SELECT dst_port, COUNT(*) AS n FROM firewall_drops WHERE ts > ? AND dst_port IS NOT NULL "
        "GROUP BY dst_port ORDER BY n DESC LIMIT 10", (cut,))

    mt = mikrotik_client.client.get() if mikrotik_client.client else {}
    pfs = mt.get("port_forwards", [])
    vpn = any((i.get("type") == "wg" or "vpn" in (i.get("name") or "").lower())
              for i in mt.get("interfaces", [])) or bool(mt.get("wireguard_peers"))

    return JSONResponse({
        "window_h": hours,
        "ids_alerts": ids_alerts,
        "ids_attackers": ids_attackers,
        "fw_drops": fw_drops,
        "attackers_dropped": attackers_dropped,
        "dropped_pct": round(attackers_dropped * 100 / ids_attackers) if ids_attackers else 0,
        "reached": len(pfs),
        "capture": "syslog" if firewall_syslog.recent() else "poll",
        "top_blocked_ports": [{"port": r["dst_port"], "count": r["n"]} for r in blocked_ports],
        "exposed": {"port_forwards": pfs, "vpn": vpn},
    })


@app.get("/api/enrich/{ip}")
def api_enrich(ip: str, force: bool = False) -> JSONResponse:
    data = enrich.lookup(ip, force=force)
    hist = store.attacker_history(ip, days=30)
    data["history"] = hist
    data["geoip"] = geo.lookup(ip)
    return JSONResponse(data)


@app.get("/api/history")
def api_history() -> JSONResponse:
    """Long-term: 30d alert trend, top attackers, top countries."""
    return JSONResponse({
        "alerts_7d": store.alerts_count_period(hours=24 * 7),
        "alerts_30d": store.alerts_count_period(hours=24 * 30),
        "top_attackers_30d": store.top_attackers_period(hours=24 * 30, limit=15),
    })


def _build_health_status() -> dict:
    """Produce a single 'how is the network right now' verdict in plain Czech.

    Levels: ok | warn | bad
    """
    issues: list[dict] = []

    # Services
    bad_services = []
    for unit, label, _ in SERVICES:
        s = service_status(unit)
        if s["active"] != "active":
            bad_services.append(label)
    if bad_services:
        issues.append({
            "level": "bad",
            "icon": "❌",
            "text": f"Služba neběží: {', '.join(bad_services)}",
        })

    # Recent critical alerts
    crit_24h = store._query(
        "SELECT COUNT(*) AS n FROM alerts WHERE ts > ? AND severity = 1",
        (time.time() - 86400,)
    )
    crit = crit_24h[0]["n"] if crit_24h else 0
    if crit > 0:
        issues.append({
            "level": "warn",
            "icon": "⚠️",
            "text": f"{crit} kritických alertů za 24h",
        })

    # Known-bad attackers (AbuseIPDB ≥ 80 or VT ≥ 5) in last 24h
    bad_attackers = store._query("""
        SELECT COUNT(DISTINCT a.src_ip) AS n
        FROM alerts a
        JOIN enrichment e ON a.src_ip = e.ip
        WHERE a.ts > ?
          AND (e.abuse_score >= 80 OR e.vt_malicious >= 5)
    """, (time.time() - 86400,))
    nbad = bad_attackers[0]["n"] if bad_attackers else 0
    if nbad > 0:
        # Firewall/IDS already blocked these → informational, NOT a warning.
        # Doesn't downgrade the banner from green.
        issues.append({
            "level": "info",
            "icon": "🛡️",
            "text": f"{nbad} škodlivých IP odraženo (firewall + IDS) · jen FYI",
        })

    # Suricata drops
    suri_iface = suricata_socket_stat()
    if suri_iface.get("drop", 0) > 0:
        issues.append({
            "level": "warn",
            "icon": "📉",
            "text": f"Suricata ztrácí pakety ({suri_iface['drop']})",
        })

    # Disk space
    disk = psutil.disk_usage("/")
    if disk.percent > 90:
        issues.append({"level": "bad", "icon": "💾", "text": f"Disk plný: {disk.percent}%"})
    elif disk.percent > 80:
        issues.append({"level": "warn", "icon": "💾", "text": f"Disk skoro plný: {disk.percent}%"})

    # MikroTik unreachable
    if mikrotik_client.client and mikrotik_client.client.get().get("last_error"):
        issues.append({
            "level": "bad", "icon": "🔌",
            "text": "MikroTik API nedostupné",
        })
    if unifi_client.client and unifi_client.client.get().get("last_error"):
        issues.append({
            "level": "warn", "icon": "📡",
            "text": "UniFi API nedostupné",
        })

    # Banner level: bad > warn > (info/none → green). Info items NEVER turn it yellow.
    _crit = store._query("SELECT COUNT(*) AS n FROM alerts WHERE ts > ? AND severity = 1", (time.time() - 3600,))
    crit_count = _crit[0]["n"] if _crit else 0   # skutečně KRITICKÉ (severity 1), konzistentní s donutem Závažnost
    new_devs_5min = len(store.devices_first_seen_recently(minutes=5))
    has_bad = any(i["level"] == "bad" for i in issues)
    has_warn = any(i["level"] == "warn" for i in issues)

    if has_bad:
        level = "bad"
        headline = "Pozor · něco nefunguje"
        sub = "Něco vyžaduje akci — viz seznam níže, klikni pro detail."
    elif has_warn:
        level = "warn"
        n_warn = sum(1 for i in issues if i["level"] == "warn")
        headline = f"Vše běží · {n_warn} {'věc ke kontrole' if n_warn == 1 else 'věci ke kontrole'}"
        sub = "Nic akutního, jen FYI · firewall + IDS drží situaci pod kontrolou."
    else:
        # Green — even if there are info chips (e.g. bad IPs blocked).
        level = "ok"
        headline = "Klid · vše OK"
        sub = (f"Posledních 60 min: ✓ {crit_count} kritických alertů · "
               f"✓ {new_devs_5min} nových zařízení · ✓ všechny služby běží. "
               "Firewall + IDS drží perimetr.")

    return {"level": level, "headline": headline, "sub": sub, "issues": issues}


def _build_events_feed(max_items: int = 20) -> list[dict]:
    """A human-readable feed of recent significant events, newest first."""
    events: list[dict] = []
    now = time.time()

    # Recent alerts grouped by source IP (within 10 min window)
    grouped = store._query("""
        SELECT src_ip, COUNT(*) AS hits, MAX(ts) AS last_ts, MAX(signature) AS sig, country_code
        FROM alerts WHERE ts > ?
        GROUP BY src_ip ORDER BY last_ts DESC LIMIT 20
    """, (now - 3600,))
    for g in grouped:
        if not g["src_ip"]:
            continue
        events.append({
            "ts": g["last_ts"],
            "icon": "🚨",
            "kind": "alert",
            "title": f"Útočník {g['src_ip']}",
            "text": f"{g['hits']}× alertů za poslední hodinu — poslední: {(g['sig'] or '?')[:50]}",
            "ip": g["src_ip"],
        })

    # Newly seen devices
    new_devs = store.devices_first_seen_recently(minutes=60)
    for d in new_devs[:10]:
        host = d.get("hostname") or "(neznámé)"
        events.append({
            "ts": d["first_seen"],
            "icon": "📱",
            "kind": "device",
            "title": "Nové zařízení v síti",
            "text": f"{host} · {d.get('ip','?')} · {d.get('vendor') or 'neznámý vendor'}",
        })

    # Firewall drop spikes
    spikes = store._query("""
        SELECT src_ip, COUNT(*) AS n, MAX(ts) AS last_ts
        FROM firewall_drops WHERE ts > ?
        GROUP BY src_ip HAVING n >= 50 ORDER BY n DESC LIMIT 5
    """, (now - 3600,))
    for s in spikes:
        events.append({
            "ts": s["last_ts"],
            "icon": "🚧",
            "kind": "firewall",
            "title": f"Firewall pětkrát dropuje {s['src_ip']}",
            "text": f"{s['n']} dropů za posledních 60 min",
            "ip": s["src_ip"],
        })

    # Recent push notifications sent
    notifs = store._query(
        "SELECT ts, kind, key, payload FROM notifications WHERE ts > ? ORDER BY ts DESC LIMIT 5",
        (now - 24 * 3600,)
    )
    for n in notifs:
        try:
            payload = json.loads(n["payload"]) if n.get("payload") else {}
        except Exception:
            payload = {}
        events.append({
            "ts": n["ts"],
            "icon": "🔔",
            "kind": "notify",
            "title": payload.get("title") or n["kind"],
            "text": (payload.get("body") or "")[:120],
        })

    events.sort(key=lambda x: x["ts"], reverse=True)
    out = []
    for e in events[:max_items]:
        # human-readable timedelta in Czech
        delta = now - (e["ts"] or now)
        if delta < 60:
            ago = "právě teď"
        elif delta < 3600:
            ago = f"před {int(delta/60)} min"
        elif delta < 86400:
            ago = f"před {int(delta/3600)} h"
        else:
            ago = f"před {int(delta/86400)} dny"
        e["ago"] = ago
        out.append(e)
    return out


@app.get("/api/health-status")
def api_health_status() -> JSONResponse:
    return JSONResponse({
        "status": _build_health_status(),
        "feed": _build_events_feed(25),
    })


@app.get("/api/now-activity")
def api_now_activity() -> JSONResponse:
    """Plain-Czech summary of 'what the system has been doing for you'."""
    now = time.time()
    h24 = now - 86400
    h1 = now - 3600

    alerts_24h = store.alerts_count_period(24)
    alerts_1h = store.alerts_count_period(1)

    drops_24h = store._query(
        "SELECT COUNT(*) AS n, COUNT(DISTINCT src_ip) AS uniq FROM firewall_drops WHERE ts > ?",
        (h24,)
    )
    drops = drops_24h[0] if drops_24h else {"n": 0, "uniq": 0}

    notifs = store._query(
        "SELECT COUNT(*) AS n FROM notifications WHERE ts > ?", (h24,)
    )
    notif_cnt = notifs[0]["n"] if notifs else 0

    ad = adguard_client.client.merged() if adguard_client.client else {}
    dns_q = ad.get("queries_24h", 0)
    dns_block = ad.get("blocked_24h", 0)

    new_devices = store.devices_first_seen_recently(minutes=24 * 60)

    return JSONResponse({
        "alerts_24h": alerts_24h,
        "alerts_1h": alerts_1h,
        "firewall_drops_24h": drops["n"],
        "firewall_unique_attackers_24h": drops["uniq"],
        "dns_queries_24h": dns_q,
        "dns_blocked_24h": dns_block,
        "dns_block_rate": round(dns_block * 100 / dns_q, 1) if dns_q else 0,
        "notifications_24h": notif_cnt,
        "new_devices_24h": len(new_devices),
        "new_devices_list": [
            {"hostname": d["hostname"] or "(neznámé)", "mac": d["mac"], "ip": d.get("ip"), "vendor": d.get("vendor"), "first_seen": d["first_seen"]}
            for d in new_devices[:5]
        ],
    })


@app.get("/api/attackers")
def api_attackers(hours: int = 24, limit: int = 300) -> JSONResponse:
    """Full attacker roll-up — every source IP that hit IDS or firewall in the window,
    merged, geo-located, threat-enriched, sorted by total hits. Powers the big
    'kdo na mě útočí a odkud' view."""
    cutoff = time.time() - hours * 3600
    # Merge IDS alerts + firewall drops per source IP in one pass
    rows = store._query("""
        SELECT src_ip AS ip,
               SUM(ids_hits) AS ids_hits,
               SUM(fw_hits)  AS fw_hits,
               MAX(last_ts)  AS last_ts
        FROM (
            SELECT src_ip, COUNT(*) AS ids_hits, 0 AS fw_hits, MAX(ts) AS last_ts
            FROM alerts WHERE ts > ? AND src_ip IS NOT NULL GROUP BY src_ip
            UNION ALL
            SELECT src_ip, 0 AS ids_hits, COUNT(*) AS fw_hits, MAX(ts) AS last_ts
            FROM firewall_drops WHERE ts > ? AND src_ip IS NOT NULL GROUP BY src_ip
        )
        GROUP BY src_ip
        ORDER BY (SUM(ids_hits) + SUM(fw_hits)) DESC
        LIMIT ?
    """, (cutoff, cutoff, limit))

    out = []
    countries: Counter = Counter()
    for r in rows:
        ip = r["ip"]
        if not ip:
            continue
        g = geo.lookup(ip)
        cc = g.get("country_code")
        if cc:
            countries[cc] += 1
        en = store.get_enrichment(ip, max_age_hours=72) or {}
        out.append({
            "ip": ip,
            "ids_hits": r["ids_hits"] or 0,
            "fw_hits": r["fw_hits"] or 0,
            "total": (r["ids_hits"] or 0) + (r["fw_hits"] or 0),
            "last_ts": r["last_ts"],
            "country": g.get("country") or "—",
            "country_code": cc,
            "flag": country_to_flag(cc),
            "city": g.get("city"),
            "asn": g.get("asn"),
            "asn_org": (g.get("asn_org") or "—"),
            "abuse_score": en.get("abuse_score"),
            "vt_malicious": en.get("vt_malicious"),
        })

    top_countries = [
        {"code": cc, "flag": country_to_flag(cc), "count": n}
        for cc, n in countries.most_common(12)
    ]
    return JSONResponse({
        "hours": hours,
        "total_ips": len(out),
        "total_hits": sum(a["total"] for a in out),
        "ids_total": sum(a["ids_hits"] for a in out),
        "fw_total": sum(a["fw_hits"] for a in out),
        "top_countries": top_countries,
        "attackers": out,
    })


@app.get("/api/known-bad-attackers")
def api_known_bad_attackers() -> JSONResponse:
    """Detail of attackers with known-bad reputation that hit us in last 24h."""
    cutoff = time.time() - 86400
    rows = store._query("""
        SELECT a.src_ip AS ip,
               COUNT(*) AS hits,
               MAX(a.ts) AS last_ts,
               MIN(a.ts) AS first_ts,
               e.abuse_score, e.abuse_reports, e.abuse_country, e.abuse_isp,
               e.vt_malicious, e.vt_country, e.vt_as_owner
        FROM alerts a
        JOIN enrichment e ON a.src_ip = e.ip
        WHERE a.ts > ?
          AND (e.abuse_score >= 80 OR e.vt_malicious >= 5)
          AND a.src_ip IS NOT NULL
        GROUP BY a.src_ip
        ORDER BY hits DESC
        LIMIT 50
    """, (cutoff,))

    # Also include known-bad from firewall drops (probably more)
    fw_rows = store._query("""
        SELECT fd.src_ip AS ip,
               COUNT(*) AS hits,
               MAX(fd.ts) AS last_ts,
               e.abuse_score, e.abuse_reports, e.abuse_country, e.abuse_isp,
               e.vt_malicious, e.vt_country, e.vt_as_owner
        FROM firewall_drops fd
        JOIN enrichment e ON fd.src_ip = e.ip
        WHERE fd.ts > ?
          AND (e.abuse_score >= 80 OR e.vt_malicious >= 5)
          AND fd.src_ip IS NOT NULL
        GROUP BY fd.src_ip
        ORDER BY hits DESC
        LIMIT 50
    """, (cutoff,))

    # Merge by IP
    merged: dict[str, dict] = {}
    for r in rows:
        merged[r["ip"]] = {**r, "source": "ids"}
    for r in fw_rows:
        if r["ip"] in merged:
            merged[r["ip"]]["hits"] += r["hits"]
            merged[r["ip"]]["source"] = "ids+fw"
        else:
            merged[r["ip"]] = {**r, "source": "fw"}

    out = []
    for ip, row in merged.items():
        g = geo.lookup(ip)
        out.append({
            "ip": ip,
            "hits": row["hits"],
            "last_ts": row["last_ts"],
            "source": row["source"],
            "country": row.get("abuse_country") or row.get("vt_country") or g.get("country"),
            "country_code": g.get("country_code"),
            "flag": country_to_flag(g.get("country_code")),
            "isp": row.get("abuse_isp") or row.get("vt_as_owner") or g.get("asn_org"),
            "abuse_score": row.get("abuse_score"),
            "abuse_reports": row.get("abuse_reports"),
            "vt_malicious": row.get("vt_malicious"),
        })
    out.sort(key=lambda x: x["hits"], reverse=True)
    return JSONResponse({"attackers": out, "count": len(out)})


@app.get("/api/dns")
def api_dns() -> JSONResponse:
    """Merged AdGuard Home stats across instances, with DHCP-hostname enrichment."""
    if not adguard_client.client:
        return JSONResponse({"configured": False, "merged": {}, "recent_queries": []})

    merged = adguard_client.client.merged()
    recent = adguard_client.client.recent_queries(60)

    # DHCP lease lookup table (IP → hostname) from MikroTik,
    # then apply manual name overrides (highest priority).
    from inventory import _NAME_OVERRIDES as _ip_overrides
    leases_by_ip: dict[str, str] = {}
    if mikrotik_client.client:
        for l in mikrotik_client.client.get().get("leases", []):
            ip = l.get("ip")
            if ip and l.get("hostname"):
                leases_by_ip[ip] = l["hostname"]
    # Manual overrides win over DHCP — e.g. gateway.home.arpa → Gateway MikroTik
    leases_by_ip.update(_ip_overrides)

    # Enrich top_clients with hostnames
    for c in merged.get("top_clients", []):
        ip = c.get("name", "")
        if ip in leases_by_ip:
            c["hostname"] = leases_by_ip[ip]
            c["ip"] = ip

    # Enrich recent_queries with client hostnames + add a "blocked" flag
    for q in recent:
        client_ip = q.get("client")
        if client_ip and client_ip in leases_by_ip:
            q["client_hostname"] = leases_by_ip[client_ip]
        # AdGuard reason field: "FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental",
        # "Rewrite", "NotFilteredNotFound" (allowed), "NotFilteredWhiteList" (allowed)
        reason = (q.get("reason") or "")
        q["blocked"] = (reason.startswith("Filtered") or reason == "Rewrite") and not reason.startswith("NotFiltered")

    return JSONResponse({
        "configured": True,
        "merged": merged,
        "recent_queries": recent,
    })


@app.get("/api/dns-history")
def api_dns_history(period: str = "24h") -> JSONResponse:
    """Period-filtered DNS volume from our own hourly history table (ADR 0008).
    Hourly buckets up to 48h, daily beyond. `summary.since` lets the UI note when
    sampling started if the requested window predates it."""
    hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}.get(period, 24)
    bucket = 3600 if hours <= 48 else 86400
    return JSONResponse({
        "period": period,
        "hours": hours,
        "bucket_seconds": bucket,
        "summary": store.dns_history_period(hours),
        "buckets": store.dns_history_buckets(hours, bucket),
    })


@app.get("/api/topology")
def api_topology() -> JSONResponse:
    """Network topology graph for D3 force layout.

    Nodes: internet, mikrotik, switches, APs, clients (collapsed to summary chips).
    Links: physical/logical hops.
    """
    mt = mikrotik_client.client.get() if mikrotik_client.client else {}
    un = unifi_client.client.get() if unifi_client.client else {}
    legacy = unifi_legacy.client.get() if unifi_legacy.client else {"clients": []}
    ad = adguard_client.client.merged() if adguard_client.client else {}

    nodes: list[dict] = []
    links: list[dict] = []

    def add(node): nodes.append(node)
    def link(s, t): links.append({"source": s, "target": t})

    # --- Curated hierarchy (confirmed by owner, ADR 0006) + live enrichment ---
    # Internet → MikroTik → {DNS×2, Monitoring .30, main switch};
    # main switch → {3× AP (WiFi7/PoE), terminal switch}.
    add({"id": "internet", "kind": "internet", "name": "Internet", "icon": "🌐"})

    res = mt.get("resource", {})
    mt_id = "mikrotik"
    add({
        "id": mt_id, "kind": "router", "name": "MikroTik hAP ax³", "icon": "🛡️",
        "detail": f"RouterOS {res.get('version','?')} · {mt.get('connections_count',0)} spojení",
        "badges": ["📶 LTE záloha", "2.5G"], "state": "ok" if res else "unknown",
        "cpu": int(res.get("cpu-load", 0)) if res.get("cpu-load") else 0,
    })
    link("internet", mt_id)

    # DNS ×2 (AdGuard) directly under MikroTik
    add({"id": "dns", "kind": "dns", "name": "DNS ×2 · AdGuard", "icon": "🛡️🌐",
         "detail": f"{ad.get('queries_24h',0):,} dotazů/24h · {ad.get('block_rate_pct',0)}% blok".replace(",", " "),
         "badges": [".11", ".21"]})
    link(mt_id, "dns")

    # Monitoring cluster node .30 directly on MikroTik port 3
    arp_ips = {a.get("ip") for a in mt.get("arp", [])}
    add({"id": "monitoring", "kind": "server", "name": "Monitoring · cluster", "icon": "🖥️",
         "detail": "192.168.50.30 · MikroTik port 3", "badges": ["cluster node"],
         "state": "ok" if "192.168.50.30" in arp_ips else "unknown"})
    link(mt_id, "monitoring")

    # UniFi infra: classify switches vs APs, then impose the confirmed hierarchy
    devices_by_mac = {(d.get("mac") or "").upper(): d for d in un.get("devices", []) if d.get("mac")}
    sw_devs, ap_devs = [], []
    for d in un.get("devices", []):
        if not d.get("id"):
            continue
        m = (d.get("model") or "").upper()
        nm = (d.get("name") or "").upper()
        (sw_devs if ("SW" in m or "USW" in m or "SWITCH" in m or "USW" in nm) else ap_devs).append(d)

    # main switch = the PoE / 8-port one ("z kterého vše běží"); the rest = koncový
    main_sw = next((d for d in sw_devs
                    if "POE" in (d.get("name") or "").upper() or " 8" in (d.get("name") or "").upper()),
                   sw_devs[0] if sw_devs else None)
    main_sw_id = main_sw["id"] if main_sw else None
    if main_sw:
        add({"id": main_sw_id, "kind": "switch", "name": main_sw.get("name") or "Hlavní switch",
             "icon": "🔀", "model": main_sw.get("model"), "ip": main_sw.get("ip"),
             "state": main_sw.get("state") or "ok", "mac": (main_sw.get("mac") or "").upper(),
             "badges": ["hlavní · 2.5G · PoE"]})
        link("dns", main_sw_id)   # LAN visí pod DNS vrstvou — „veškerý provoz přes DNS"
    parent = main_sw_id or "dns"

    for d in sw_devs:
        if d is main_sw:
            continue
        add({"id": d["id"], "kind": "switch", "name": d.get("name") or "Switch", "icon": "🔀",
             "model": d.get("model"), "ip": d.get("ip"), "state": d.get("state") or "ok",
             "mac": (d.get("mac") or "").upper(), "badges": ["koncový · 2.5G"]})
        link(parent, d["id"])

    for d in ap_devs:
        add({"id": d["id"], "kind": "ap", "name": d.get("name") or "AP", "icon": "📶",
             "model": d.get("model"), "ip": d.get("ip"), "state": d.get("state") or "ok",
             "mac": (d.get("mac") or "").upper(), "badges": ["WiFi 7 · PoE"]})
        link(parent, d["id"])

    # Client bubbles per AP (WiFi) and per switch (wired)
    have = {n["id"] for n in nodes}
    wifi_per_ap: dict[str, int] = {}
    wired_per_sw: dict[str, int] = {}
    for c in legacy.get("clients", []):
        if c.get("is_wired"):
            sw = devices_by_mac.get((c.get("sw_mac") or "").upper())
            if sw:
                wired_per_sw[sw["id"]] = wired_per_sw.get(sw["id"], 0) + 1
        else:
            ap = devices_by_mac.get((c.get("ap_mac") or "").upper())
            if ap:
                wifi_per_ap[ap["id"]] = wifi_per_ap.get(ap["id"], 0) + 1
    for ap_id, cnt in wifi_per_ap.items():
        if ap_id in have:
            bid = f"clients-wifi-{ap_id}"
            add({"id": bid, "kind": "clients", "name": f"{cnt} 📶", "icon": "👥", "detail": f"{cnt} WiFi klientů"})
            link(ap_id, bid)
    for sw_id, cnt in wired_per_sw.items():
        if sw_id in have:
            bid = f"clients-wired-{sw_id}"
            add({"id": bid, "kind": "clients", "name": f"{cnt} 🔌", "icon": "👥", "detail": f"{cnt} drátových klientů"})
            link(sw_id, bid)

    # Logická (ne-stromová) hrana: monitoring taky používá DNS → čárkovaná šipka PŘÍMO na DNS
    # (ne přes switch). Frontend ji dokreslí přes layout uzlů.
    extra_links = [{"source": "dns", "target": "monitoring"}]
    return JSONResponse({"nodes": nodes, "links": links, "extra_links": extra_links})


@app.get("/api/trends")
def api_trends() -> JSONResponse:
    return JSONResponse(trends.all_trends())


@app.get("/api/talkers")
def api_talkers() -> JSONResponse:
    """Top per-device talkers from ntopng + DPI app breakdown."""
    if not ntopng_client.client:
        return JSONResponse({"configured": False, "top_talkers": [], "apps": [], "system": {}})
    snap = ntopng_client.client.get()
    # Enrich top talkers with hostname from inventory if available
    mt = mikrotik_client.client.get() if mikrotik_client.client else {}
    un = unifi_client.client.get() if unifi_client.client else {}
    devs = inventory.build(mt, un) if (mt or un) else []
    by_ip = {d.get("ip"): d for d in devs if d.get("ip")}
    for t in snap.get("top_talkers", []):
        ip = t.get("ip")
        # Manual name override wins (e.g. gateway.home.arpa → Gateway MikroTik)
        if ip and ip in inventory._NAME_OVERRIDES:
            t["hostname"] = inventory._NAME_OVERRIDES[ip]
        elif ip in by_ip:
            d = by_ip[ip]
            t["hostname"] = d.get("hostname") or t.get("name")
            t["mac"] = d.get("mac")
            t["vendor"] = d.get("vendor")
    return JSONResponse({
        "configured": True,
        "top_talkers": snap.get("top_talkers", [])[:15],
        "apps": snap.get("apps", [])[:15],
        "system": snap.get("system_stats", {}),
        "last_error": snap.get("last_error"),
    })


@app.get("/api/attacker-geo")
def api_attacker_geo() -> JSONResponse:
    """GeoIP-located attacker points for globe visualization."""
    points: list[dict] = []
    for row in trends.attacker_geo_points(hours=24, limit=200):
        ip = row.get("ip")
        if not ip:
            continue
        g = geo.lookup(ip)
        if g.get("lat") is None or g.get("lon") is None:
            continue
        points.append({
            "ip": ip,
            "hits": row.get("hits", 0),
            "lat": g["lat"],
            "lon": g["lon"],
            "country": g.get("country"),
            "country_code": g.get("country_code"),
            "city": g.get("city"),
            "asn_org": g.get("asn_org"),
        })
    return JSONResponse({"points": points, "count": len(points)})


@app.get("/api/monthly-traffic")
def api_monthly_traffic(month: str | None = None) -> JSONResponse:
    """Top per-device traffic for given YYYY-MM (default current)."""
    devs = store.monthly_device_traffic(month)
    # Enrich with hostname/MAC from inventory (talkers may have nicer names)
    mt = mikrotik_client.client.get() if mikrotik_client.client else {}
    un = unifi_client.client.get() if unifi_client.client else {}
    invs = inventory.build(mt, un) if (mt or un) else []
    by_ip = {d.get("ip"): d for d in invs if d.get("ip")}
    for d in devs:
        ip = d.get("ip")
        if ip in by_ip:
            inv = by_ip[ip]
            if inv.get("hostname") and inv["hostname"] != inv.get("mac"):
                d["name"] = inv["hostname"]
            if inv.get("vendor"):
                d["vendor"] = inv["vendor"]
            d["uplink"] = inv.get("uplink")
    return JSONResponse({
        "month": month or time.strftime("%Y-%m", time.localtime()),
        "devices": devs[:30],
        "total_tx": sum(d["tx_bytes"] for d in devs),
        "total_rx": sum(d["rx_bytes"] for d in devs),
    })


@app.get("/api/internet-usage")
def api_internet_usage() -> JSONResponse:
    """Trustworthy traffic only: WAN (ether5) + VPN (wireguard) byte counters
    straight from the router, for this calendar month, last month and rolling
    windows. Per-device / internal-LAN is intentionally NOT reported — we have no
    flow-grade source for it (see ADR 0003), and a wrong number is worse than none.
    """
    now = time.localtime()
    this_m = time.strftime("%Y-%m", now)
    y, mo = now.tm_year, now.tm_mon
    last_m = f"{y - 1}-12" if mo == 1 else f"{y}-{mo - 1:02d}"

    def pack(cat: str) -> dict:
        return {
            "mtd":  store.interface_traffic_month(cat, this_m),
            "last": store.interface_traffic_month(cat, last_m),
            "d24h": store.interface_traffic_period(cat, 24),
            "d7d":  store.interface_traffic_period(cat, 24 * 7),
            "d30d": store.interface_traffic_period(cat, 24 * 30),
        }

    # Daily WAN buckets for the current month → fuels the Ø/den figure, end-of-month
    # projection and the per-day sparkline on the WAN card (all from the trustworthy
    # ether5 counter; distinct from the period-driven Provoz card).
    import calendar
    month_start = time.mktime((y, mo, 1, 0, 0, 0, 0, 0, -1))
    hours_since = max(1.0, (time.time() - month_start) / 3600)
    wan_daily = store.interface_traffic_history("wan", hours_since, 86400)
    days_in_month = calendar.monthrange(y, mo)[1]

    return JSONResponse({
        "this_month": this_m,
        "day_of_month": now.tm_mday,
        "days_in_month": days_in_month,
        "wan_daily": wan_daily,
        "last_month": last_m,
        "wan": pack("wan"),
        "vpn": pack("vpn"),
        "per_device_available": False,
        "note": ("Per-device a interní LAN se záměrně neměří: chybí flow-grade zdroj "
                 "z routeru (MikroTik Traffic-Flow je vypnutý, per-IP accounting na ROS7 "
                 "není). Ukazujeme jen WAN a VPN countery z routeru, kterým lze věřit."),
    })


@app.get("/api/device-inet")
def api_device_inet(hours: int = 24) -> JSONResponse:
    """REAL per-device internet traffic (down/up) from the NetFlow v9 collector (ADR 0007).
    MikroTik Traffic-Flow → udp/2055 → collector → store.db; per-device via NAT field 226."""
    devs = store.device_inet_period(hours)
    mt = mikrotik_client.client.get() if mikrotik_client.client else {}
    un = unifi_client.client.get() if unifi_client.client else {}
    invs = inventory.build(mt, un) if (mt or un) else []
    by_ip = {d.get("ip"): d for d in invs if d.get("ip")}
    for d in devs:
        inv = by_ip.get(d["ip"])
        if inv:
            d["name"] = inv.get("hostname") or inv.get("name")
            d["vendor"] = inv.get("vendor")
        else:
            d["name"] = inventory._NAME_OVERRIDES.get(d["ip"])   # katalog i pro statické IP mimo inventář
    return JSONResponse({
        "devices": devs[:40],
        "total_down": sum(d["down_bytes"] for d in devs),
        "total_up": sum(d["up_bytes"] for d in devs),
        "window_h": hours,
        "collector": netflow_collector.collector.health(),
    })


PERIOD_TO_HOURS = {
    "1h":  1,
    "6h":  6,
    "24h": 24,
    "7d":  24 * 7,
    "30d": 24 * 30,
    "boot": None,  # cumulative since router boot
}

# Bucket size for the time-series chart per period (so we always get ~30–48 points)
PERIOD_BUCKETS = {
    "1h":  60 * 5,           # 5 min buckets → 12 points
    "6h":  60 * 15,          # 15 min        → 24
    "24h": 60 * 60,          # 1 h           → 24
    "7d":  60 * 60 * 6,      # 6 h           → 28
    "30d": 60 * 60 * 24,     # 1 d           → 30
}


@app.get("/api/firewall-rules")
def api_firewall_rules() -> JSONResponse:
    """MikroTik firewall filter rules with hit counts (bytes + packets per rule)."""
    mt = mikrotik_client.client.get() if mikrotik_client.client else {}
    rules = mt.get("firewall_rules", [])
    out = []
    for r in rules:
        if r.get("dynamic") or r.get("invalid") or r.get("disabled"):
            continue
        out.append({
            "chain":   r.get("chain"),
            "action":  r.get("action"),
            "comment": r.get("comment") or "(bez komentáře)",
            "bytes":   r.get("bytes", 0),
            "packets": r.get("packets", 0),
        })
    # Group by chain → sort by bytes desc, take all
    out.sort(key=lambda x: x["bytes"], reverse=True)
    return JSONResponse({
        "rules": out,
        "total_bytes":   sum(r["bytes"] for r in out),
        "total_packets": sum(r["packets"] for r in out),
        "chain_counts":  {
            c: sum(1 for r in out if r["chain"] == c)
            for c in {r["chain"] for r in out}
        }
    })


@app.get("/api/wall-of-shame")
def api_wall_of_shame(hours: float | None = None) -> JSONResponse:
    """All enriched attackers with VT or AbuseIPDB data — paginated grid for the UI.
    `hours` restricts to IPs that actually hit the IDS within the window (Security
    tab period filter); None = every known-bad IP in the enrichment cache."""
    base_select = """
        SELECT e.ip, e.abuse_score, e.abuse_reports, e.abuse_country, e.abuse_isp,
               e.vt_malicious, e.vt_suspicious, e.vt_country, e.vt_as_owner,
               e.fetched_at,
               (SELECT COUNT(*) FROM alerts a WHERE a.src_ip = e.ip) AS our_hits,
               (SELECT MAX(ts) FROM alerts a WHERE a.src_ip = e.ip) AS last_hit
        FROM enrichment e
        WHERE (COALESCE(e.abuse_score, 0) > 0 OR COALESCE(e.vt_malicious, 0) > 0)
    """
    order = " ORDER BY COALESCE(e.abuse_score,0)*COALESCE(e.vt_malicious,1) DESC LIMIT 200"
    if hours:
        rows = store._query(
            base_select + " AND e.ip IN (SELECT DISTINCT src_ip FROM alerts WHERE ts > ?)" + order,
            (time.time() - hours * 3600,),
        )
    else:
        rows = store._query(base_select + order)
    out = []
    for r in rows:
        g = geo.lookup(r["ip"]) if r["ip"] else {}
        score = r.get("abuse_score") or 0
        vt = r.get("vt_malicious") or 0
        # Threat tier
        if score >= 80 or vt >= 5:
            tier = "critical"
        elif score >= 50 or vt >= 2:
            tier = "high"
        elif score > 0 or vt > 0:
            tier = "medium"
        else:
            tier = "clean"
        out.append({
            "ip": r["ip"],
            "tier": tier,
            "abuse_score":  score,
            "abuse_reports": r.get("abuse_reports") or 0,
            "vt_malicious": vt,
            "vt_suspicious": r.get("vt_suspicious") or 0,
            "country": r.get("abuse_country") or r.get("vt_country") or g.get("country_code"),
            "flag":    country_to_flag(g.get("country_code")),
            "isp":     r.get("abuse_isp") or r.get("vt_as_owner") or g.get("asn_org"),
            "our_hits": r.get("our_hits") or 0,
            "last_hit": r.get("last_hit"),
            "fetched_at": r.get("fetched_at"),
        })
    return JSONResponse({
        "total":    len(out),
        "critical": sum(1 for a in out if a["tier"] == "critical"),
        "high":     sum(1 for a in out if a["tier"] == "high"),
        "medium":   sum(1 for a in out if a["tier"] == "medium"),
        "clean":    sum(1 for a in out if a["tier"] == "clean"),
        "attackers": out,
    })


@app.get("/api/wan-lan-summary")
def api_wan_lan_summary(period: str = "24h") -> JSONResponse:
    """WAN/LAN/VPN traffic totals.

    period = 1h | 6h | 24h | 7d | 30d → delta-summed from SQLite snapshots
    period = boot                       → cumulative MikroTik counters since boot
    """
    mt = mikrotik_client.client.get() if mikrotik_client.client else {}
    ifaces = mt.get("interfaces", [])

    if period == "boot" or period not in PERIOD_TO_HOURS:
        # Live cumulative from MikroTik counters
        wan_rx = wan_tx = lan_rx = lan_tx = vpn_rx = vpn_tx = 0
        wan_ifs, lan_ifs, vpn_ifs = [], [], []
        for i in ifaces:
            name = (i.get("name") or "").lower()
            kind = i.get("type") or ""
            comment = (i.get("comment") or "").lower()
            rx, tx = i.get("rx_byte") or 0, i.get("tx_byte") or 0
            if "wan" in comment or name == "ether5":
                wan_rx += rx; wan_tx += tx; wan_ifs.append(i.get("name"))
            elif kind == "wg" or "vpn" in comment or "vpn" in name:
                vpn_rx += rx; vpn_tx += tx; vpn_ifs.append(i.get("name"))
            elif kind == "bridge":
                # LAN = bridge aggregate ONLY — summing member ports + vlans would
                # double/triple-count the same frames (RouterOS counters overlap).
                lan_rx += rx; lan_tx += tx; lan_ifs.append(i.get("name"))
        return JSONResponse({
            "period": "boot",
            "wan": {"rx_bytes": wan_rx, "tx_bytes": wan_tx, "interfaces": wan_ifs},
            "lan": {"rx_bytes": lan_rx, "tx_bytes": lan_tx, "interfaces": lan_ifs},
            "vpn": {"rx_bytes": vpn_rx, "tx_bytes": vpn_tx, "interfaces": vpn_ifs},
        })

    # Delta-summed from SQLite snapshots over the period
    hours = PERIOD_TO_HOURS[period]
    wan = store.interface_traffic_period("wan", hours)
    lan = store.interface_traffic_period("lan", hours)
    vpn = store.interface_traffic_period("vpn", hours)
    return JSONResponse({
        "period": period,
        "wan": {**wan, "interfaces": [i["name"] for i in wan["interfaces"]]},
        "lan": {**lan, "interfaces": [i["name"] for i in lan["interfaces"]]},
        "vpn": {**vpn, "interfaces": [i["name"] for i in vpn["interfaces"]]},
    })


@app.get("/api/wan-lan-history")
def api_wan_lan_history(period: str = "24h") -> JSONResponse:
    """Time-series buckets for WAN/LAN/VPN over the period."""
    if period not in PERIOD_BUCKETS:
        period = "24h"
    hours = PERIOD_TO_HOURS[period]
    bucket = PERIOD_BUCKETS[period]
    return JSONResponse({
        "period": period,
        "bucket_seconds": bucket,
        "wan": store.interface_traffic_history("wan", hours, bucket),
        "lan": store.interface_traffic_history("lan", hours, bucket),
        "vpn": store.interface_traffic_history("vpn", hours, bucket),
    })


@app.get("/api/flow-matrix")
def api_flow_matrix() -> JSONResponse:
    """Top device-to-internet flow pairs based on ntopng hosts + DNS top clients.

    For homelab this means: top local device → top external ASNs they reach.
    """
    if not ntopng_client.client:
        return JSONResponse({"matrix": [], "configured": False})
    snap = ntopng_client.client.get()
    hosts = snap.get("hosts_local", [])
    matrix = []
    for h in hosts[:15]:
        if (h.get("tx_bytes") or 0) + (h.get("rx_bytes") or 0) == 0:
            continue
        name = h.get("name") or h.get("ip") or "?"
        if name.startswith("fe80:"):
            continue
        matrix.append({
            "ip": h.get("ip"),
            "name": name.split(" ")[0],
            "tx_bytes": h.get("tx_bytes", 0),
            "rx_bytes": h.get("rx_bytes", 0),
            "active_flows": h.get("active_flows", 0),
            "country": h.get("country"),
        })
    matrix.sort(key=lambda x: x["tx_bytes"] + x["rx_bytes"], reverse=True)
    return JSONResponse({"matrix": matrix[:15], "configured": True})


@app.get("/api/health")
def api_health() -> JSONResponse:
    """Rich health probe — DB size, WAL, threads, data freshness, integration status."""
    import threading
    db = config.STORE_DB_PATH
    db_mb = round(db.stat().st_size / 1024 / 1024, 1) if db.exists() else 0
    wal = db.with_suffix(".db-wal")
    wal_mb = round(wal.stat().st_size / 1024 / 1024, 1) if wal.exists() else 0

    last_alert = store.latest_alert_ts()
    last_alert_age = round(time.time() - last_alert) if last_alert else None

    def _client_ok(c):
        if not c:
            return None
        snap = c.get()
        return snap.get("last_error") is None

    integrations = {
        "mikrotik": _client_ok(mikrotik_client.client),
        "unifi": _client_ok(unifi_client.client),
        "unifi_legacy": _client_ok(unifi_legacy.client),
        "ntopng": _client_ok(ntopng_client.client),
        "adguard": bool(adguard_client.client and adguard_client.client.merged().get("instances_running")),
    }
    bad = [k for k, v in integrations.items() if v is False]
    status = "degraded" if bad else "ok"

    return JSONResponse({
        "status": status,
        "degraded_integrations": bad,
        "db_mb": db_mb,
        "wal_mb": wal_mb,
        "threads": threading.active_count(),
        "rss_mb": round(psutil.Process().memory_info().rss / 1024 / 1024, 1),
        "last_alert_age_s": last_alert_age,
        "alerts_24h": store.alerts_count_period(24),
        "integrations": integrations,
        "uptime_s": round(time.time() - psutil.boot_time()),
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8889, log_level="info")
