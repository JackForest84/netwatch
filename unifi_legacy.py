"""UniFi *legacy* API (cookie-based login).

Needed because the Network Integration API doesn't expose per-client signal,
TX/RX rates, retries, DPI categories — that data lives on the old
`/api/s/{site}/stat/sta` and friends.
"""

from __future__ import annotations

import time
import urllib3
from threading import Lock, Thread
from typing import Any

import requests

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UnifiLegacyClient:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.verify = False
        self.timeout = 8
        self.base = config.UNIFI_URL
        self.site = config.UNIFI_LEGACY_SITE
        self.logged_in = False
        self.lock = Lock()
        self.snapshot: dict[str, Any] = {
            "clients": [],
            "rogue_aps": [],
            "events": [],
            "last_fetch": None,
            "last_error": None,
        }
        Thread(target=self._loop, daemon=True).start()

    def _login(self) -> bool:
        try:
            # UniFi OS uses /api/auth/login + X-CSRF-Token header
            r = self.session.post(
                f"{self.base}/api/auth/login",
                json={
                    "username": config.UNIFI_LEGACY_USER,
                    "password": config.UNIFI_LEGACY_PASS,
                    "remember": False,
                },
                timeout=self.timeout,
            )
            if r.status_code != 200:
                self.logged_in = False
                return False
            csrf = r.headers.get("x-csrf-token") or r.headers.get("X-CSRF-Token")
            if csrf:
                self.session.headers["X-CSRF-Token"] = csrf
            self.logged_in = True
            return True
        except Exception:
            self.logged_in = False
            return False

    def _get(self, path: str) -> Any:
        url = f"{self.base}/proxy/network{path}"
        for _ in range(2):
            if not self.logged_in and not self._login():
                raise RuntimeError("UniFi legacy login failed")
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code in (401, 403):
                self.logged_in = False
                continue
            r.raise_for_status()
            new_csrf = r.headers.get("x-updated-csrf-token")
            if new_csrf:
                self.session.headers["X-CSRF-Token"] = new_csrf
            return r.json()
        raise RuntimeError("UniFi legacy auth retry exhausted")

    def _fetch_all(self) -> dict[str, Any]:
        data: dict[str, Any] = {}

        # Connected clients with full detail
        try:
            raw = self._get(f"/api/s/{self.site}/stat/sta")
            clients: list[dict] = []
            for c in (raw.get("data") or []):
                clients.append({
                    "mac": (c.get("mac") or "").upper(),
                    "ip": c.get("ip"),
                    "hostname": c.get("hostname") or c.get("name"),
                    "ap_mac": (c.get("ap_mac") or "").upper(),
                    "sw_mac": (c.get("sw_mac") or "").upper(),
                    "sw_port": c.get("sw_port"),
                    "is_wired": c.get("is_wired"),
                    "is_guest": c.get("is_guest"),
                    "radio": c.get("radio"),
                    "radio_proto": c.get("radio_proto"),
                    "channel": c.get("channel"),
                    "signal": c.get("signal"),
                    "noise": c.get("noise"),
                    "rssi": c.get("rssi"),
                    "tx_rate_kbps": (c.get("tx_rate") or 0) // 1000 if c.get("tx_rate") else 0,
                    "rx_rate_kbps": (c.get("rx_rate") or 0) // 1000 if c.get("rx_rate") else 0,
                    "tx_retries": c.get("tx_retries"),
                    "tx_packets": c.get("tx_packets"),
                    "rx_packets": c.get("rx_packets"),
                    "tx_bytes": c.get("tx_bytes") or c.get("wired-tx_bytes") or 0,
                    "rx_bytes": c.get("rx_bytes") or c.get("wired-rx_bytes") or 0,
                    "uptime": c.get("uptime"),
                    "last_seen": c.get("last_seen"),
                    "essid": c.get("essid"),
                    "vlan": c.get("vlan"),
                    "dpi_app": (c.get("dpi") or {}).get("app"),
                    "dpi_cat": (c.get("dpi") or {}).get("cat"),
                })
            data["clients"] = clients
        except Exception:
            data["clients"] = []

        # Rogue/neighbour APs
        try:
            raw = self._get(f"/api/s/{self.site}/stat/rogueap")
            data["rogue_aps"] = raw.get("data") or []
        except Exception:
            data["rogue_aps"] = []

        # Recent events (sessions, anomalies)
        try:
            raw = self._get(f"/api/s/{self.site}/stat/event?within=24&_limit=200")
            events = []
            for e in (raw.get("data") or [])[:200]:
                events.append({
                    "time": e.get("time"),
                    "key": e.get("key"),
                    "msg": e.get("msg"),
                    "subsystem": e.get("subsystem"),
                    "ap": e.get("ap"),
                    "ap_name": e.get("ap_name"),
                    "guest": e.get("guest"),
                    "user": e.get("user"),
                })
            data["events"] = events
        except Exception:
            data["events"] = []

        data["last_fetch"] = time.time()
        return data

    def _loop(self) -> None:
        while True:
            try:
                snap = self._fetch_all()
                with self.lock:
                    snap["last_error"] = None
                    self.snapshot = snap
            except Exception as e:
                with self.lock:
                    self.snapshot["last_error"] = str(e)
                    self.snapshot["last_fetch"] = time.time()
            time.sleep(config.API_POLL_SECONDS)

    def get(self) -> dict[str, Any]:
        with self.lock:
            return dict(self.snapshot)


client = UnifiLegacyClient() if config.UNIFI_LEGACY_USER and config.UNIFI_LEGACY_PASS else None
