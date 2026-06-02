"""System / service status helpers: systemd, Redis, Suricata socket stats, net sampler."""
from __future__ import annotations
import json
import subprocess
import time
from datetime import datetime
from threading import Lock, Thread
from typing import Any
import psutil

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
